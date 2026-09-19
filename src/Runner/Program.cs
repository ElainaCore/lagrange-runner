using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Lagrange.Core;
using Lagrange.Core.Common;
using Lagrange.Core.Common.Interface;
using Lagrange.Core.Common.Entity;
using Lagrange.Core.Events.EventArgs;
using Lagrange.Core.Message;
using Lagrange.Core.Message.Entities;
using Lagrange.Core.Utility;

namespace RunnerWin;

/// <summary>自建签名服务器 Provider（与 Lagrange.Core DefaultBotSignProvider 契约一致）。</summary>
internal class SelfHostSignProvider : BotSignProvider
{
    // Keep the request shape identical on Windows and Linux.  Some nginx/
    // Python http.server combinations mishandle HTTP/2 or chunked requests,
    // which used to make only the Linux runner fail at the sign endpoint.
    private readonly HttpClient _client = new()
    {
        Timeout = TimeSpan.FromSeconds(10),
        DefaultRequestVersion = HttpVersion.Version11,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };
    private readonly string _url;

    public SelfHostSignProvider(string url) => _url = url.TrimEnd('/');

    public override bool IsWhiteListCommand(string cmd) => SignWhitelist.Commands.Contains(cmd);

    public override async Task<SsoSecureInfo?> GetSecSign(long uin, string cmd, int seq, ReadOnlyMemory<byte> body)
    {
        var payload = new JsonObject
        {
            ["cmd"] = cmd,
            ["seq"] = seq,
            ["src"] = Convert.ToHexString(body.Span),
        };

        try
        {
            // Serialize directly to UTF-8 bytes and set Content-Length
            // explicitly.  This avoids platform-dependent request encoding
            // and transfer framing in the Linux .NET HTTP stack.
            var requestBody = JsonSerializer.SerializeToUtf8Bytes(payload);
            using var content = new ByteArrayContent(requestBody);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };
            content.Headers.ContentLength = requestBody.Length;
            using var response = await _client.PostAsync(_url, content);
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                // stdout is reserved for JSON-RPC frames; diagnostics must
                // stay on stderr or the manager will parse them as protocol
                // responses and lose login events.
                Console.Error.WriteLine($"[sign] {cmd} -> HTTP {(int)response.StatusCode}: {error}");
                throw new InvalidOperationException($"sign server returned HTTP {(int)response.StatusCode}");
            }

            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            if (!json.TryGetProperty("value", out var value))
                throw new InvalidOperationException("sign server response does not contain value");

            static byte[] ReadHex(JsonElement value, string name)
            {
                if (!value.TryGetProperty(name, out var field))
                    throw new InvalidOperationException($"sign server response does not contain {name}");
                var hex = field.GetString();
                if (string.IsNullOrWhiteSpace(hex))
                    throw new InvalidOperationException($"sign server returned empty {name}");
                try
                {
                    return Convert.FromHexString(hex);
                }
                catch (FormatException ex)
                {
                    throw new InvalidOperationException($"sign server returned invalid {name}", ex);
                }
            }

            return new SsoSecureInfo
            {
                SecSign = ReadHex(value, "sign"),
                SecToken = ReadHex(value, "token"),
                SecExtra = ReadHex(value, "extra"),
            };
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[sign] {cmd} -> {e.Message}");
            throw;
        }
    }
}

/// <summary>多 bot JSON-RPC 守护进程。</summary>
internal static class Program
{
    // 全局帧格式: 每行一个 JSON（stdin 请求 / stdout 响应与事件），协议端自身日志走 stderr
    private static readonly Dictionary<string, BotInstance> Bots = new();
    private static readonly Dictionary<string, TaskCompletionSource<JsonObject?>> Pending = new();
    private static readonly object Gate = new();

    private sealed class BotInstance
    {
        public required string Id;
        public required BotContext Context;
        public required string DataDir;
    }

    private static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        var signUrl = Environment.GetEnvironmentVariable("SIGN_SERVER_URL") ?? "http://127.0.0.1:8080";
        var dataRoot = Environment.GetEnvironmentVariable("RUNNER_DATA_ROOT") ?? ".";

        // Read synchronously so a redirected stdin line is consumed before an
        // EOF can terminate the process. Keep request handling concurrent and
        // wait for all queued work before exiting on EOF.
        var pending = new List<Task>();
        while (Console.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            pending.Add(Task.Run(() => HandleLineSafely(line, signUrl, dataRoot)));
        }

        Task.WaitAll(pending.ToArray());
    }

    private static void HandleLineSafely(string line, string signUrl, string dataRoot)
    {
        try
        {
            HandleLine(line, signUrl, dataRoot).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            try
            {
                var json = JsonNode.Parse(line) as JsonObject;
                var id = json?["id"]?.ToString() ?? "";
                Write(new JsonObject { ["id"] = id, ["error"] = e.Message });
            }
            catch
            {
                Write(new JsonObject { ["error"] = e.Message });
            }
        }
    }

    private static async Task HandleLine(string line, string signUrl, string dataRoot)
    {
        JsonObject req;
        try { req = (JsonNode.Parse(line) as JsonObject)!; }
        catch { Write(new JsonObject { ["error"] = "invalid json" }); return; }

        var id = req["id"]?.ToString() ?? "";
        var method = req["method"]?.ToString() ?? "";
        var p = req["params"] as JsonObject ?? [];

        switch (method)
        {
            case "ping": Write(new JsonObject { ["id"] = id, ["result"] = "pong" }); break;

            case "bot.create": await CreateBot(id, p, signUrl, dataRoot); break;
            case "bot.login.qr": await LoginQr(id, p); break;
            case "bot.login.resume": await LoginResume(id, p); break;
            case "bot.login.password": await LoginPassword(id, p); break;
            case "bot.submit.captcha": SubmitCaptcha(id, p); break;
            case "bot.submit.sms": SubmitSms(id, p); break;
            case "bot.stop": await StopBot(id, p); break;
            case "bot.list": ListBots(id); break;
            case "bot.info": BotInfo(id, p); break;
            case "bot.friend.list": await FriendList(id, p); break;
            case "bot.group.list": await GroupList(id, p); break;
            case "bot.group.info": await GroupInfo(id, p); break;
            case "bot.group.member.list": await GroupMemberList(id, p); break;
            case "bot.group.member.info": await GroupMemberInfo(id, p); break;
            case "bot.stranger.info": await StrangerInfo(id, p); break;
            case "bot.group.kick": await GroupKick(id, p); break;
            case "bot.group.ban": await GroupBan(id, p); break;
            case "bot.group.whole_ban": await GroupWholeBan(id, p); break;
            case "bot.group.card": await GroupCard(id, p); break;
            case "bot.group.special_title": await GroupSpecialTitle(id, p); break;
            case "bot.group.name": await GroupName(id, p); break;
            case "bot.group.leave": await GroupLeave(id, p); break;
            case "bot.group.poke": await GroupPoke(id, p); break;
            case "bot.friend.poke": await FriendPoke(id, p); break;
            case "bot.status.set": await SetStatus(id, p); break;
            case "bot.friend.request.list": await FriendRequestList(id, p); break;
            case "bot.group.remark": await GroupRemark(id, p); break;
            case "bot.group.todo.set": await GroupTodoSet(id, p); break;
            case "bot.group.todo.get": await GroupTodoGet(id, p); break;
            case "bot.group.todo.finish": await GroupTodoFinish(id, p); break;
            case "bot.group.todo.remove": await GroupTodoRemove(id, p); break;
            case "bot.group.reaction": await GroupReaction(id, p); break;
            case "bot.friend.pin": await FriendPin(id, p); break;
            case "bot.group.pin": await GroupPin(id, p); break;
            case "bot.group.clockin": await GroupClockIn(id, p); break;
            case "bot.group.atall": await GroupAtAll(id, p); break;
            case "bot.cookies": await Cookies(id, p); break;
            case "bot.client.key": await ClientKey(id, p); break;
            case "msg.history.group": await GroupHistory(id, p); break;
            case "msg.history.private": await PrivateHistory(id, p); break;
            case "packet.send": await SendPacket(id, p); break;

            case "msg.send.group": await SendGroup(id, p); break;
            case "msg.send.private": await SendPrivate(id, p); break;
            case "msg.send.group.image": await SendGroupImage(id, p); break;
            case "msg.send.segments": await SendSegments(id, p); break;
            case "msg.send.forward": await SendForward(id, p); break;
            case "msg.recall": await Recall(id, p); break;

            default: Write(new JsonObject { ["id"] = id, ["error"] = $"unknown method: {method}" }); break;
        }
    }

    // ---------- bot 生命周期 ----------

    private static Task CreateBot(string id, JsonObject p, string signUrl, string dataRoot)
    {
        var botId = p["bot_id"]?.ToString() ?? throw new ArgumentException("bot_id required");
        lock (Gate)
        {
            if (Bots.ContainsKey(botId)) throw new InvalidOperationException($"bot {botId} already exists");
        }

        var dir = Path.Combine(dataRoot, botId);
        Directory.CreateDirectory(dir);
        var keystorePath = Path.Combine(dir, "keystore.json");
        var keystore = File.Exists(keystorePath)
            ? JsonSerializer.Deserialize<BotKeystore>(File.ReadAllText(keystorePath)) ?? BotKeystore.CreateEmpty()
            : BotKeystore.CreateEmpty();

        var context = BotFactory.Create(new BotConfig
        {
            Protocol = Protocols.Linux,
            LogLevel = LogLevel.Information,
            SignProvider = new SelfHostSignProvider(signUrl),
        }, keystore);

        var instance = new BotInstance { Id = botId, Context = context, DataDir = dir };
        RegisterEvents(instance);
        lock (Gate) Bots[botId] = instance;

        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["bot_id"] = botId, ["created"] = true } });
        return Task.CompletedTask;
    }

    private static void RegisterEvents(BotInstance bot)
    {
        var ctx = bot.Context;

        ctx.EventInvoker.RegisterEvent<BotLogEvent>((_, e) =>
            Console.Error.WriteLine($"[{bot.Id}] {e}"));

        ctx.EventInvoker.RegisterEvent<BotQrCodeEvent>((_, e) =>
        {
            Write(new JsonObject
            {
                ["event"] = "qr.code",
                ["bot_id"] = bot.Id,
                ["url"] = e.Url,
                ["png_base64"] = Convert.ToBase64String(e.Image),
            });
        });

        ctx.EventInvoker.RegisterEvent<BotQrCodeQueryEvent>((_, e) =>
            Write(new JsonObject { ["event"] = "qr.state", ["bot_id"] = bot.Id, ["state"] = e.State.ToString() }));

        ctx.EventInvoker.RegisterEvent<BotLoginEvent>((_, e) =>
            Write(new JsonObject
            {
                ["event"] = "login.result",
                ["bot_id"] = bot.Id,
                ["success"] = e.Success,
                ["state"] = e.State,
                ["error"] = e.Error == null ? null : $"{e.Error?.Tag}: {e.Error?.Message}",
            }));

        ctx.EventInvoker.RegisterEvent<BotOnlineEvent>((_, e) =>
            Write(new JsonObject { ["event"] = "bot.online", ["bot_id"] = bot.Id, ["uin"] = bot.Context.BotUin, ["reason"] = e.Reason.ToString() }));

        ctx.EventInvoker.RegisterEvent<BotOfflineEvent>((_, e) =>
            Write(new JsonObject
            {
                ["event"] = "bot.offline",
                ["bot_id"] = bot.Id,
                ["reason"] = e.Reason.ToString(),
                ["tips"] = e.Tips == null ? null : $"{e.Tips?.Tag}: {e.Tips?.Message}",
            }));

        ctx.EventInvoker.RegisterEvent<BotCaptchaEvent>((_, e) =>
            Write(new JsonObject { ["event"] = "login.captcha", ["bot_id"] = bot.Id, ["url"] = e.CaptchaUrl }));

        ctx.EventInvoker.RegisterEvent<BotSMSEvent>((_, e) =>
            Write(new JsonObject { ["event"] = "login.sms", ["bot_id"] = bot.Id, ["phone"] = e.Phone, ["url"] = e.Url }));

        ctx.EventInvoker.RegisterEvent<BotNewDeviceVerifyEvent>((_, e) =>
            Write(new JsonObject { ["event"] = "login.new_device", ["bot_id"] = bot.Id, ["url"] = e.Url }));

        ctx.EventInvoker.RegisterEvent<BotRefreshKeystoreEvent>(async (_, e) =>
        {
            var path = Path.Combine(bot.DataDir, "keystore.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(e.Keystore));
            Write(new JsonObject { ["event"] = "keystore.refreshed", ["bot_id"] = bot.Id });
        });

        ctx.EventInvoker.RegisterEvent<BotMessageEvent>((_, e) =>
        {
            var data = SerializeMessage(e.Message);
            if (e.Message.Contact is BotGroupMember member)
            {
                data["group_id"] = member.Group.GroupUin;
                data["role"] = member.Permission.ToString();
            }
            Write(new JsonObject { ["event"] = "message", ["bot_id"] = bot.Id, ["uin"] = bot.Context.BotUin, ["data"] = data });
        });

        // 其它 Lagrange 事件统一携带 OneBot v11 payload 转发。这样通知、
        // 请求与撤回不会因为 runner 只认识 message 而在桥接层静默丢失。
        ctx.EventInvoker.RegisterEvent<BotFriendRecallEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "friend_recall",
                ["user_id"] = e.AuthorUin, ["message_id"] = e.Sequence.ToString(), ["tip"] = e.Tip,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupRecallEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "group_recall",
                ["group_id"] = e.GroupUin, ["user_id"] = e.AuthorUin, ["operator_id"] = e.OperatorUin,
                ["message_id"] = e.Sequence.ToString(), ["tip"] = e.Tip,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupMemberIncreaseEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "group_increase",
                ["sub_type"] = e.Type == 2 ? "invite" : "approve", ["group_id"] = e.GroupUin,
                ["user_id"] = e.MemberUin, ["operator_id"] = e.OperatorUin, ["invitor_id"] = e.InvitorUin,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupMemberDecreaseEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "group_decrease",
                ["sub_type"] = e.UserUin == bot.Context.BotUin ? "leave" : (e.OperatorUin is null or 0 ? "leave" : "kick"),
                ["group_id"] = e.GroupUin, ["user_id"] = e.UserUin, ["operator_id"] = e.OperatorUin,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupNudgeEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "notify", ["sub_type"] = "poke",
                ["group_id"] = e.GroupUin, ["user_id"] = e.OperatorUin, ["target_id"] = e.TargetUin,
                ["action"] = e.Action, ["suffix"] = e.Suffix,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupReactionEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "notice", ["notice_type"] = "notify", ["sub_type"] = "group_reaction",
                ["group_id"] = e.TargetGroupUin, ["user_id"] = e.OperatorUin,
                ["message_id"] = e.TargetSequence.ToString(), ["code"] = e.Code,
                ["is_add"] = e.IsAdd, ["count"] = e.CurrentCount,
            }));

        ctx.EventInvoker.RegisterEvent<BotFriendRequestEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "request", ["request_type"] = "friend",
                ["user_id"] = e.InitiatorUin, ["comment"] = e.Message, ["flag"] = e.Source,
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupJoinNotificationEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "request", ["request_type"] = "group", ["sub_type"] = "add",
                ["group_id"] = e.Notification.GroupUin, ["user_id"] = e.Notification.TargetUin,
                ["comment"] = e.Notification.Comment, ["flag"] = e.Notification.Sequence.ToString(),
            }));

        ctx.EventInvoker.RegisterEvent<BotGroupInviteNotificationEvent>((_, e) =>
            WriteOneBot(bot, new JsonObject
            {
                ["post_type"] = "request", ["request_type"] = "group", ["sub_type"] = "invite",
                ["group_id"] = e.Notification.GroupUin, ["user_id"] = e.Notification.InviterUin,
                ["comment"] = "", ["flag"] = e.Notification.Sequence.ToString(),
            }));
    }

    private static void WriteOneBot(BotInstance bot, JsonObject payload)
    {
        payload["time"] ??= DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        payload["self_id"] ??= bot.Context.BotUin;
        Write(new JsonObject
        {
            ["event"] = "onebot", ["bot_id"] = bot.Id, ["uin"] = bot.Context.BotUin,
            ["payload"] = payload,
        });
    }

    private static async Task LoginQr(string id, JsonObject p)
    {
        var bot = GetBot(p);
        _ = ObserveLogin(bot, bot.Context.Login());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["started"] = true } });
        await Task.CompletedTask;
    }

    private static async Task LoginResume(string id, JsonObject p)
    {
        var bot = GetBot(p);
        // 与扫码入口共用 Login()：有有效 keystore 时走快速重登，失效时
        // 才会回退到二维码流程。无论最终结果如何都向管理器报告。
        _ = ObserveLogin(bot, bot.Context.Login());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["started"] = true } });
        await Task.CompletedTask;
    }

    private static async Task LoginPassword(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var uin = p["uin"]?.GetValue<long>() ?? throw new ArgumentException("uin required");
        var password = p["password"]?.ToString() ?? throw new ArgumentException("password required");
        _ = ObserveLogin(bot, bot.Context.Login(uin, password));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["started"] = true } });
        await Task.CompletedTask;
    }

    private static async Task ObserveLogin(BotInstance bot, Task<bool> loginTask)
    {
        try
        {
            var success = await loginTask.ConfigureAwait(false);
            if (!success)
            {
                Write(new JsonObject
                {
                    ["event"] = "login.completed",
                    ["bot_id"] = bot.Id,
                    ["success"] = false,
                    ["uin"] = bot.Context.BotUin,
                    ["error"] = "登录鉴权完成，但未能完成在线注册（InfoSync）",
                });
            }
            else
            {
                Write(new JsonObject
                {
                    ["event"] = "login.completed",
                    ["bot_id"] = bot.Id,
                    ["success"] = true,
                    ["uin"] = bot.Context.BotUin,
                });
            }
        }
        catch (Exception e)
        {
            Write(new JsonObject
            {
                ["event"] = "login.completed",
                ["bot_id"] = bot.Id,
                ["success"] = false,
                ["uin"] = bot.Context.BotUin,
                ["error"] = e.Message,
            });
        }
    }

    private static void SubmitCaptcha(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var ok = bot.Context.SubmitCaptcha(
            p["ticket"]?.ToString() ?? throw new ArgumentException("ticket required"),
            p["randstr"]?.ToString() ?? "");
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["submitted"] = ok } });
    }

    private static void SubmitSms(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var ok = bot.Context.SubmitSMSCode(p["code"]?.ToString() ?? throw new ArgumentException("code required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["submitted"] = ok } });
    }

    private static async Task StopBot(string id, JsonObject p)
    {
        var bot = GetBot(p);
        try { await bot.Context.Logout(); } catch { /* 已离线等情况忽略 */ }
        lock (Gate) Bots.Remove(bot.Id);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["stopped"] = true } });
    }

    private static void ListBots(string id)
    {
        lock (Gate)
        {
            var list = new JsonArray();
            foreach (var b in Bots.Values)
                list.Add(new JsonObject { ["bot_id"] = b.Id, ["uin"] = b.Context.BotUin });
            Write(new JsonObject { ["id"] = id, ["result"] = list });
        }
    }

    private static void BotInfo(string id, JsonObject p)
    {
        var bot = GetBot(p);
        Write(new JsonObject
        {
            ["id"] = id,
            ["result"] = new JsonObject { ["user_id"] = bot.Context.BotUin, ["nickname"] = "" },
        });
    }

    private static async Task FriendList(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var friends = await bot.Context.FetchFriends(p["no_cache"]?.GetValue<bool>() ?? false);
        var result = new JsonArray();
        foreach (var friend in friends)
        {
            result.Add(new JsonObject
            {
                ["user_id"] = friend.Uin,
                ["nickname"] = friend.Nickname,
                ["remark"] = friend.Remarks,
            });
        }
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static JsonObject SerializeGroup(BotGroup group)
    {
        return new JsonObject
        {
            ["group_id"] = group.GroupUin,
            ["group_name"] = group.GroupName,
            ["member_count"] = group.MemberCount,
            ["max_member_count"] = group.MaxMember,
            ["group_remark"] = group.GroupRemark ?? "",
            ["description"] = group.Description ?? "",
        };
    }

    private static async Task GroupList(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groups = await bot.Context.FetchGroups(p["no_cache"]?.GetValue<bool>() ?? false);
        var result = new JsonArray();
        foreach (var group in groups) result.Add(SerializeGroup(group));
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static async Task GroupInfo(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var groups = await bot.Context.FetchGroups(p["no_cache"]?.GetValue<bool>() ?? false);
        var group = groups.FirstOrDefault(item => item.GroupUin == groupUin)
            ?? throw new InvalidOperationException($"group {groupUin} not found");
        Write(new JsonObject { ["id"] = id, ["result"] = SerializeGroup(group) });
    }

    private static JsonObject SerializeMember(BotGroupMember member)
    {
        var role = member.Permission switch
        {
            GroupMemberPermission.Owner => "owner",
            GroupMemberPermission.Admin => "admin",
            _ => "member",
        };
        return new JsonObject
        {
            ["group_id"] = member.Group.GroupUin,
            ["user_id"] = member.Uin,
            ["nickname"] = member.Nickname,
            ["card"] = member.MemberCard ?? "",
            ["role"] = role,
            ["permission"] = role,
            ["title"] = member.SpecialTitle ?? "",
            ["level"] = member.GroupLevel,
            ["join_time"] = member.JoinTime,
            ["last_sent_time"] = member.LastMsgTime,
            ["shut_up_timestamp"] = member.ShutUpTimestamp,
        };
    }

    private static async Task GroupMemberList(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var members = await bot.Context.FetchMembers(groupUin, p["no_cache"]?.GetValue<bool>() ?? false);
        var result = new JsonArray();
        foreach (var member in members) result.Add(SerializeMember(member));
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static async Task GroupMemberInfo(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var memberUin = p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required");
        var members = await bot.Context.FetchMembers(groupUin, p["no_cache"]?.GetValue<bool>() ?? false);
        var member = members.FirstOrDefault(item => item.Uin == memberUin)
            ?? throw new InvalidOperationException($"member {memberUin} not found in group {groupUin}");
        Write(new JsonObject { ["id"] = id, ["result"] = SerializeMember(member) });
    }

    private static async Task StrangerInfo(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var userUin = p["user_uin"]?.GetValue<long>() ?? throw new ArgumentException("user_uin required");
        var stranger = await bot.Context.FetchStranger(userUin);
        Write(new JsonObject
        {
            ["id"] = id,
            ["result"] = new JsonObject
            {
                ["user_id"] = stranger.Uin,
                ["nickname"] = stranger.Nickname,
                ["sex"] = stranger.Gender.ToString().ToLowerInvariant(),
                ["age"] = (long)stranger.Age,
                ["qid"] = stranger.QID,
                ["level"] = (long)stranger.Level,
                ["city"] = stranger.City,
            },
        });
    }

    private static async Task GroupKick(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var ok = await bot.Context.KickGroupMember(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required"),
            p["reject_add"]?.GetValue<bool>() ?? false,
            p["reason"]?.ToString() ?? "");
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = ok } });
    }

    private static async Task GroupBan(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var ok = await bot.Context.MuteGroupMember(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required"),
            p["duration"]?.GetValue<uint>() ?? 1800);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = ok } });
    }

    private static async Task GroupWholeBan(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var ok = await bot.Context.MuteGroupGlobal(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["enable"]?.GetValue<bool>() ?? true);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = ok } });
    }

    private static async Task GroupCard(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.GroupMemberRename(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required"),
            p["card"]?.ToString() ?? "");
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupSpecialTitle(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.GroupSetSpecialTitle(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required"),
            p["title"]?.ToString() ?? "");
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupName(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.GroupRename(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["name"]?.ToString() ?? "");
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupLeave(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.GroupQuit(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupPoke(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SendGroupNudge(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["member_uin"]?.GetValue<long>() ?? throw new ArgumentException("member_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task FriendPoke(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SendFriendNudge(
            p["user_uin"]?.GetValue<long>() ?? throw new ArgumentException("user_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task SetStatus(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var status = p["status"]?.GetValue<uint>() ?? throw new ArgumentException("status required");
        var ok = p["text"] is JsonNode text
            ? await bot.Context.SetCustomStatus(p["face_id"]?.GetValue<uint>() ?? 0, text.ToString())
            : await bot.Context.SetStatus(status);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = ok } });
    }

    private static async Task FriendRequestList(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var requests = await bot.Context.FetchFriendRequests();
        var result = new JsonArray();
        foreach (var request in requests)
        {
            result.Add(new JsonObject
            {
                ["user_id"] = request.SourceUin,
                ["target_id"] = request.TargetUin,
                ["comment"] = request.Comment,
                ["source"] = request.Source,
                ["time"] = request.Time,
                ["state"] = request.EventState.ToString(),
            });
        }
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static async Task GroupRemark(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.RemarkGroup(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["remark"]?.ToString() ?? string.Empty);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupTodoSet(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SetGroupTodo(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["sequence"]?.GetValue<ulong>() ?? throw new ArgumentException("sequence required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupTodoGet(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var todo = await bot.Context.GetGroupTodo(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject
        { ["group_id"] = todo.GroupUin, ["sequence"] = todo.Sequence, ["preview"] = todo.Preview } });
    }

    private static async Task GroupTodoFinish(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.FinishGroupTodo(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupTodoRemove(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.RemoveGroupTodo(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupReaction(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SetGroupReaction(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["sequence"]?.GetValue<ulong>() ?? throw new ArgumentException("sequence required"),
            p["code"]?.ToString() ?? throw new ArgumentException("code required"),
            p["enable"]?.GetValue<bool>() ?? true);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task FriendPin(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SetPinFriend(
            p["friend_uin"]?.GetValue<long>() ?? throw new ArgumentException("friend_uin required"),
            p["enable"]?.GetValue<bool>() ?? true);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupPin(string id, JsonObject p)
    {
        var bot = GetBot(p);
        await bot.Context.SetPinGroup(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"),
            p["enable"]?.GetValue<bool>() ?? true);
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["success"] = true } });
    }

    private static async Task GroupClockIn(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var result = await bot.Context.GroupClockIn(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject
        {
            ["success"] = result.IsSuccess, ["title"] = result.Title,
            ["keep_day_text"] = result.KeepDayText, ["group_rank_text"] = result.GroupRankText,
            ["clock_in_time"] = result.ClockInTime, ["detail_url"] = result.DetailUrl,
        } });
    }

    private static async Task GroupAtAll(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var result = await bot.Context.GroupRemainAtAll(
            p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required"));
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject
        { ["remain_at_all_count_for_uin"] = result.RemainAtAllCountForUin,
          ["remain_at_all_count_for_group"] = result.RemainAtAllCountForGroup } });
    }

    private static async Task Cookies(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var domains = new List<string>();
        if (p["domains"] is JsonArray values)
            domains.AddRange(values.Select(value => value?.ToString() ?? string.Empty).Where(value => !string.IsNullOrWhiteSpace(value)));
        if (domains.Count == 0 && !string.IsNullOrWhiteSpace(p["domain"]?.ToString()))
            domains.Add(p["domain"]!.ToString());
        if (domains.Count == 0) domains.Add("qun.qq.com");
        var result = await bot.Context.FetchCookies(domains);
        var output = new JsonObject();
        foreach (var pair in result) output[pair.Key] = pair.Value;
        Write(new JsonObject { ["id"] = id, ["result"] = output });
    }

    private static async Task ClientKey(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var result = await bot.Context.FetchClientKey();
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject
        { ["key"] = result.Key, ["expiration"] = result.Expiration } });
    }

    private static async Task GroupHistory(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var group = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var start = p["message_seq"]?.GetValue<ulong>() ?? 0;
        var count = p["count"]?.GetValue<ulong>() ?? 20;
        var messages = await bot.Context.GetGroupMessage(group, start, start + count);
        var result = new JsonArray();
        foreach (var message in messages) result.Add(SerializeMessage(message));
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static async Task PrivateHistory(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var user = p["user_uin"]?.GetValue<long>() ?? throw new ArgumentException("user_uin required");
        var start = p["message_seq"]?.GetValue<ulong>() ?? 0;
        var count = p["count"]?.GetValue<ulong>() ?? 20;
        var messages = await bot.Context.GetC2CMessage(user, start, start + count);
        var result = new JsonArray();
        foreach (var message in messages) result.Add(SerializeMessage(message));
        Write(new JsonObject { ["id"] = id, ["result"] = result });
    }

    private static async Task SendPacket(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var command = p["cmd"]?.ToString()?.Trim();
        var encoded = p["data"]?.ToString()?.Trim();
        if (string.IsNullOrWhiteSpace(command) || string.IsNullOrWhiteSpace(encoded))
            throw new ArgumentException("cmd/data required");

        encoded = encoded.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? encoded[2..] : encoded;
        if (encoded.Length % 2 != 0 || encoded.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("data must be hexadecimal");

        var body = Convert.FromHexString(encoded);
        var response = await bot.Context.SendPacket(new BotSsoPacket(command, body));
        Write(new JsonObject
        {
            ["id"] = id,
            ["result"] = new JsonObject
            {
                ["cmd"] = response.Command,
                ["data"] = Convert.ToHexString(response.Data.ToArray()).ToLowerInvariant(),
                ["sequence"] = response.Sequence,
                ["retcode"] = response.RetCode,
            }
        });
    }

    // ---------- 消息 API ----------

    private static async Task SendGroup(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var text = p["text"]?.ToString() ?? "";
        var result = await bot.Context.SendGroupMessage(groupUin, new MessageBuilder().Text(text).Build());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["sequence"] = result.Sequence } });
    }

    private static async Task SendPrivate(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var friendUin = p["friend_uin"]?.GetValue<long>() ?? throw new ArgumentException("friend_uin required");
        var text = p["text"]?.ToString() ?? "";
        var result = await bot.Context.SendFriendMessage(friendUin, new MessageBuilder().Text(text).Build());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["sequence"] = result.Sequence } });
    }

    private static async Task SendGroupImage(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>() ?? throw new ArgumentException("group_uin required");
        var bytes = Convert.FromBase64String(p["image_base64"]?.ToString() ?? throw new ArgumentException("image_base64 required"));
        var result = await bot.Context.SendGroupMessage(groupUin, new MessageBuilder().Image(bytes).Build());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["sequence"] = result.Sequence } });
    }

    private static async Task SendSegments(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var group = p["group_uin"]?.GetValue<long>();
        var friend = p["friend_uin"]?.GetValue<long>();
        var arr = p["segments"] as JsonArray ?? throw new ArgumentException("segments required");

        var builder = new MessageBuilder();
        foreach (var node in arr)
        {
            var seg = node as JsonObject ?? throw new ArgumentException("segment must be object");
            var type = seg["type"]?.ToString();
            switch (type)
            {
                case "text":
                    builder.Text(seg["data"]?.ToString() ?? "");
                    break;
                case "at":
                {
                    var qq = seg["qq"]?.ToString() ?? "0";
                    if (!long.TryParse(qq, out var uin))
                        throw new ArgumentException("at segment qq must be numeric");
                    // 带上展示文本，确保 Lagrange 生成完整的 @实体；部分 QQ
                    // 客户端/官方机器人网关会忽略没有 display 的提及。
                    var display = seg["name"]?.ToString();
                    builder.Mention(uin, string.IsNullOrWhiteSpace(display) ? qq : display);
                    break;
                }
                case "at_all":
                    builder.Mention(0, null); // 0 = 全体成员
                    break;
                case "image":
                {
                    var b64 = seg["data_base64"]?.ToString();
                    if (string.IsNullOrEmpty(b64)) throw new ArgumentException("image segment needs data_base64");
                    builder.Image(Convert.FromBase64String(b64));
                    break;
                }
                case "json":
                    builder += new LightAppEntity(seg["data"]?.ToString() ?? "");
                    break;
                default:
                    throw new ArgumentException($"unsupported segment type: {type}");
            }
        }

        var result = group.HasValue
            ? await bot.Context.SendGroupMessage(group.Value, builder.Build())
            : await bot.Context.SendFriendMessage(friend ?? 0, builder.Build());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["sequence"] = result.Sequence } });
    }

    private static MessageChain BuildForwardChain(JsonArray segments)
    {
        var builder = new MessageBuilder();
        foreach (var node in segments)
        {
            if (node is not JsonObject seg) continue;
            var type = seg["type"]?.ToString();
            var data = seg["data"] as JsonObject ?? [];
            switch (type)
            {
                case "text":
                    builder.Text(data["text"]?.ToString() ?? "");
                    break;
                case "at":
                    var qq = data["qq"]?.ToString() ?? "0";
                    builder.Mention(qq == "all" ? 0 : long.Parse(qq), data["name"]?.ToString());
                    break;
                case "image":
                {
                    var value = data["file"]?.ToString() ?? "";
                    if (value.StartsWith("base64://", StringComparison.OrdinalIgnoreCase))
                        value = value["base64://".Length..];
                    if (!string.IsNullOrWhiteSpace(value)) builder.Image(Convert.FromBase64String(value));
                    break;
                }
                case "json":
                    builder += new LightAppEntity(data["data"]?.ToString() ?? "");
                    break;
            }
        }
        return builder.Build();
    }

    private static async Task SendForward(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var group = p["group_uin"]?.GetValue<long>();
        var friend = p["friend_uin"]?.GetValue<long>();
        var nodes = p["messages"] as JsonArray ?? throw new ArgumentException("messages required");
        var messages = new List<BotMessage>();
        foreach (var node in nodes)
        {
            if (node is not JsonObject item) continue;
            var data = item["data"] as JsonObject ?? [];
            var content = data["content"] as JsonArray ?? [];
            var name = data["name"]?.ToString() ?? "";
            var uin = long.TryParse(data["uin"]?.ToString(), out var parsedUin) ? parsedUin : 0;
            var chain = BuildForwardChain(content);
            messages.Add(group.HasValue
                ? BotMessage.CreateCustomGroup(group.Value, uin, name, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), chain)
                : BotMessage.CreateCustomFriend(uin, name, friend ?? 0, "", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), chain));
        }

        var builder = new MessageBuilder().MultiMsg(messages);
        var result = group.HasValue
            ? await bot.Context.SendGroupMessage(group.Value, builder.Build())
            : await bot.Context.SendFriendMessage(friend ?? 0, builder.Build());
        Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["sequence"] = result.Sequence } });
    }

    private static async Task Recall(string id, JsonObject p)
    {
        var bot = GetBot(p);
        var groupUin = p["group_uin"]?.GetValue<long>();
        var seq = p["sequence"]?.GetValue<ulong>() ?? throw new ArgumentException("sequence required");
        try
        {
            if (groupUin.HasValue)
            {
                // 拉取目标消息后按 BotMessage 撤回（近期消息窗口内有效）
                var msgs = await bot.Context.GetGroupMessage(groupUin.Value, seq - 2, seq + 1);
                var target = msgs.FirstOrDefault(m => m.Sequence == seq);
                if (target == null) throw new InvalidOperationException("message not found in recent window");
                await bot.Context.RecallMessage(target);
                Write(new JsonObject { ["id"] = id, ["result"] = new JsonObject { ["recalled"] = true } });
            }
            else
            {
                Write(new JsonObject { ["id"] = id, ["error"] = "private recall not supported yet" });
            }
        }
        catch (Exception e)
        {
            Write(new JsonObject { ["id"] = id, ["error"] = $"recall failed: {e.Message}" });
        }
        await Task.CompletedTask;
    }

    private static BotInstance GetBot(JsonObject p)
    {
        var botId = p["bot_id"]?.ToString() ?? throw new ArgumentException("bot_id required");
        lock (Gate)
        {
            if (!Bots.TryGetValue(botId, out var bot)) throw new InvalidOperationException($"bot {botId} not exists");
            return bot;
        }
    }

    // ---------- 序列化 ----------

    private static JsonObject SerializeMessage(BotMessage m)
    {
        var entities = new JsonArray();
        foreach (var entity in m.Entities)
        {
            var obj = entity switch
            {
                TextEntity t => new JsonObject { ["type"] = "text", ["text"] = t.Text },
                MentionEntity men => new JsonObject { ["type"] = "mention", ["uin"] = men.Uin, ["display"] = men.Display },
                ImageEntity img => new JsonObject
                {
                    ["type"] = "image", ["url"] = img.FileUrl, ["file_id"] = img.FileUuid,
                    ["size"] = img.FileSize, ["summary"] = img.Summary,
                },
                RecordEntity rec => new JsonObject { ["type"] = "record", ["url"] = rec.FileUrl, ["file_id"] = rec.FileUuid },
                LightAppEntity la => new JsonObject { ["type"] = "json", ["data"] = la.Payload },
                ReplyEntity rep => new JsonObject { ["type"] = "reply", ["seq"] = rep.SrcSequence },
                _ => new JsonObject { ["type"] = entity.GetType().Name },
            };
            entities.Add(obj);
        }

        var contact = new JsonObject { ["uin"] = m.Contact.Uin, ["nickname"] = m.Contact.Nickname };
        if (m.Contact is BotGroupMember member)
        {
            contact["group_uin"] = member.Group.GroupUin;
            contact["group_name"] = member.Group.GroupName;
            contact["card"] = member.MemberCard;
            contact["permission"] = member.Permission.ToString();
            contact["group_level"] = member.GroupLevel;
            contact["special_title"] = member.SpecialTitle;
        }

        return new JsonObject
        {
            ["type"] = m.Type.ToString(),          // Group / Private / Temp
            ["self_uin"] = m.Receiver.Uin,          // Bot 自己
            ["contact"] = contact,
            ["time"] = m.Time,
            ["sequence"] = m.Sequence,
            ["entities"] = entities,
        };
    }

    private static void Write(JsonObject obj)
    {
        lock (Gate)
        {
            Console.Out.WriteLine(obj.ToJsonString());
            Console.Out.Flush();
        }
    }
}
