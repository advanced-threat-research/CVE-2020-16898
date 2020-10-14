function init(args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

function match(args)
    local packet = args["packet"]
    if packet == nil then
        print("Packet buffer empty! Aborting...")
        return 0
    end

    -- SCPacketPayload starts at byte 5 of the ICMPv6 header, so we use the packet buffer instead.
    local buffer = SCPacketPayload()
    local search_str = string.sub(buffer, 1, 8)
    local s, _ = string.find(packet, search_str, 1, true)
    local offset = s - 4

    -- Only inspect Router Advertisement (Type = 134) ICMPv6 packets.
    local type = tonumber(packet:byte(offset))
    if type ~= 134 then
        return 0
    end

    -- ICMPv6 Options start at byte 17 of the ICMPv6 payload.
    offset = offset + 16

    -- Continue looking for Options until we've run out of packet bytes.
    while offset < string.len(packet) do

        -- We're only interested in RDNSS Options (Type = 25).
        local option_type = tonumber(packet:byte(offset))

        -- The Option's Length field counts in 8-byte increments, so Length = 2 means the Option is 16 bytes long.
        offset = offset + 1
        local length = tonumber(packet:byte(offset))

        -- The vulnerability is exercised when an even length value is in an RDNSS Option.
        if option_type == 25 and length > 3 and (length % 2) == 0 then
            return 1

        -- Otherwise, move to the start of the next Option, if present.
        else
            offset = offset + (length * 8) - 1
        end
    end

    return 0
end
