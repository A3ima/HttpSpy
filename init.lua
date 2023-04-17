assert(syn or http, "Unsupported exploit (should support syn.request or http.request)");

local options = ({...})[1] or { AutoDecode = true, Highlighting = true, SaveLogs = true, CLICommands = true, ShowResponse = true, BlockedURLs = {}, API = true };
local version = "v1.1.3";
local logname = string.format("%d-%s-log.txt", game.PlaceId, os.date("%d_%m_%y"));


local format, gsub, match, append, Type, Pairs, Pcall, Error, getnamecallmethod =
    string.format, string.gsub, string.match, appendfile, type, pairs, pcall, error, getnamecallmethod;

if options.SaveLogs then
    writefile(logname, format("Http Logs from %s\n\n", os.date("%d/%m/%y"))) 
end;

local Serializer = loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/leopard/main/rbx/leopard-syn.lua"))();
local clonef = clonefunction;
local pconsole = clonef(rconsoleprint);
local crunning = clonef(coroutine.running);
local cwrap = clonef(coroutine.wrap);
local cresume = clonef(coroutine.resume);
local cyield = clonef(coroutine.yield);
local blocked = options.BlockedURLs;
local enabled = true;
local reqfunc = (syn or http).request;
local libtype = syn and "syn" or "http";
local hooked = {};
local proxied = {};
local methods = {
    HttpGet = not syn,
    HttpGetAsync = not syn,
    GetObjects = true,
    HttpPost = not syn,
    HttpPostAsync = not syn
}

Serializer.UpdateConfig({ highlighting = options.Highlighting });

local RecentCommit = game.HttpService:JSONDecode(game:HttpGet("https://api.github.com/repos/NotDSF/HttpSpy/commits?per_page=1&path=init.lua"))[1].commit.message;
local OnRequest = Instance.new("BindableEvent");

local function printf(...) 
    if options.SaveLogs then
        append(logname, gsub(format(...), "%\27%[%d+m", ""));
    end;
    return pconsole(format(...));
end;

local __namecall, __request;
__namecall = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
    local method = getnamecallmethod();

    if methods[method] then
        printf("game:%s(%s)\n\n", method, Serializer.FormatArguments(...));
    end;

    return __namecall(self, ...);
end));

__request = hookfunction(reqfunc, newcclosure(function(req) 
    if Type(req) ~= "table" then return __request(req); end;
    
    local RequestData = DeepCopy(req);
    if not enabled then
        return __request(req);
    end;

    if Type(RequestData.Url) ~= "string" or blocked[RequestData.Url] then
        printf("%s.request(%s) -- blocked url\n\n", libtype, Serializer.Serialize(RequestData));
        return __request(req);
    end;

    local t = crunning();
    cwrap(function() 
        if RequestData.Url then
            local Host = match(RequestData.Url, "https?://(%w+.%w+)/");
            if Host and proxied[Host] then
                RequestData.Url = gsub(RequestData.Url, Host, proxied[Host], 1);
            end;
        end;

        OnRequest:Fire(RequestData);

        local ok, ResponseData = Pcall(__request, RequestData);
        if not ok then
            Error(ResponseData, 0);
        end;

        local BackupData = {};
        for i, v in Pairs(ResponseData) do
            BackupData[i] = v;
        end;

        if BackupData.Headers["Content-Type"] and match(BackupData.Headers["Content-Type"], "application/json") and options.AutoDecode then
            local body = BackupData.Body;
            local ok, res = Pcall(game.HttpService.JSONDecode, game.HttpService, body);
            if ok then
                BackupData.Body = res;
            end;
        end;

        printf("%s.request(%s)\n\nResponse Data: %s\n\n", libtype, Serializer.Serialize(RequestData), Serializer.Serialize(BackupData));
        cresume(t, hooked[RequestData.Url] and hooked[RequestData.Url](ResponseData) or ResponseData);
    end)();
    return cyield();
end));

if request then
    replaceclosure(request, reqfunc);
end;

local API = {};
API.OnRequest = OnRequest.Event;

API.__index = API;

function API:HookSynRequest(url, hook)
    hooked[url] = hook;
end;

function API:ProxyHost(host, proxy)
    proxied[host] = proxy;
end;

function API:RemoveProxy(host)
    if not proxied[host] then
        error("host isn't proxied", 0);
    end;
    proxied[host] = nil;
end;

function API:UnHookSynRequest(url)
    if not hooked[url] then
        error("url isn't hooked", 0);
    end;
    hooked[url] = nil;
end

function API:BlockUrl(url)
    blocked[url] = true;
end;

function API:WhitelistUrl(url)
    blocked[url] = false;
end;

return setmetatable(API, API);
