-- Initialize the pseudo random number generator - http://lua-users.org/wiki/MathLibraryTutorial
local hmac = require "openssl".hmac
local base64 = require "base64"

---- Require the CSV library
--local csv = require "lua-csv.csv"

local counter = 0
local thread_counter = 0
local threads = {}
local algo = "sha1"
local key = "3S2I773IIDU9SUA22P9H"
local secret = "LaxMdsGVvGQnqCroO8uDmm4jOdrYSCLQ4u3JmMNO"

local function split(str, sep)
	local result = {}
	for match in (str..sep):gmatch("(.-)"..sep) do
		table.insert(result, match)
	end
	return result
end

function file_exists(file)
	local f = io.open(file, "rb")
	if f then f:close() end
	return f ~= nil
end

function shuffle(paths)
	local j, k
	local n = #paths
	for i = 1, n do
	j, k = math.random(n), math.random(n)
	paths[j], paths[k] = paths[k], paths[j]
	end
	return paths
end

function non_empty_lines_from(file)
	if not file_exists(file) then return {} end
	lines = {}
	for line in io.lines(file) do
	if not (line == '') then
		lines[#lines + 1] = line
	end
	end
	return lines
end

function setup(thread)
	thread:set("id", thread_counter)
	hosts = split(os.getenv("hosts"), ",")
	port = os.getenv("port")
	addrs = wrk.lookup(hosts[math.random(#hosts)], port)
	for i = #addrs, 1, -1 do
		if not wrk.connect(addrs[i]) then
			table.remove(addrs, i)
		end
	end

	thread.addr = addrs[#addrs]

	table.insert(threads, thread)
	thread_counter = thread_counter + 1
end

function init(args)
	math.randomseed(os.time())
	--math.random(); math.random(); math.random()
	counter = 0

	input_file = os.getenv("s3_objects_input_file")
	paths = non_empty_lines_from(input_file)
	--paths = shuffle(paths)

	if #paths <= 0 then
		print("multiplepaths: No paths found. You have to create a file paths.txt with one path per line")
		os.exit()
	end
	init_done = 0
	counter = 0
 
	--print("multiplepaths: Found " .. #paths .. " paths")
end

request = function()
	local tid = wrk.thread:get("id")
--	if init_done == 0 then
--		math.randomseed(os.time() + tid)
--		counter = math.random(#paths)
--		init_done = 1
--	end

	counter = counter + 1
	path = paths[counter]
	if counter >= #paths then
		counter = 0
	end
	wrk.method = "GET"
	wrk.path = path
	wrk.headers["Content-Type"] = "binary/octave"
	wrk.headers['Date'] = os.date("%a, %d %b %Y %H:%M:%S +0000")

	local stringToSign = "GET\n\n" .. wrk.headers["Content-Type"] .. "\n" .. wrk.headers['Date'] .. "\n" .. wrk.path
	--local cmd = "echo -en \"" .. stringToSign .. "\" | openssl sha1 -hmac V1E9046sDVBVENp2rwY45XnxvyqPoECgiNBy9GKx --binary | base64"
	local signature = base64.encode(hmac.hmac(algo, stringToSign, secret, true))

	wrk.headers['Authorization'] = "AWS " .. key .. ":" .. signature

	--print(tid .. " " .. counter .. " " .. path)
	return wrk.format(wrk.method, wrk.path, wrk.headers)
end
