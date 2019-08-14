-- tpcstream.lua

-- main code from https://meetup.toast.com/posts/103
-- Wireshark로 내가 만든 프로토콜 분석하기(Wireshark Custom Dissector 제작)

----------------------------------------------
-- (1) Create ToastPC Streaming protocol
--  "tpcstream" : 프로토콜 이름. Filter 창 등에서 사용
--  "TPCSTREAM" : Packet Detail, List의 Protocol 컬럼에 표시될 프로토콜 Description
p_tpcstream = Proto("tpcstream", "TPCSTREAM")

 -- https://wiki.wireshark.org/LuaAPI/Proto#Proto
 -- Proto.new(name, desc) : Creates a new protocol
 --  name : string : The name of the protocol 
 --  desc : string : A Long Text description of the protocol (usually lowercase) 


----------------------------------------------
-- (2) 필드 정의하기
-- 위에서 만든 "p_tpcstream" 객체의 Field를 정의합니다.
local f = p_tpcstream.fields

-- Field 정의
--   HEADER 공통
--     STARTCODE Field 정의
f.startcode  = ProtoField.uint32("tpcstream.startcode", "STARTCODE", base.HEX)
 -- ProtoField.uint32() : unsigned 32bit(=4 byte) 크기의 필드
 -- Wireshark의 'tree' 영역에 표시되는 이름 : "tpcstream.startcode"
 -- Wireshark의 'filter' 에 적용되는 이름 : "STARTCODE"
 -- base.HEX : 16진수로 표기함

-- https://wiki.wireshark.org/LuaAPI/Proto#ProtoField
-- ProtoField.new(name, abbr, type, [voidstring], [base], [mask], [descr])
--  name : Actual name of the field (the string that appears in the tree). 
--  abbr : Filter name of the field (the string that is used in filters). 
--  type : Field Type: one of ftypes.NONE, ftypes.PROTOCOL, ftypes.BOOLEAN, ftypes.UINT8, ftypes.UINT16, ftypes.UINT24, ftypes.UINT32, ftypes.UINT64, ftypes.INT8, ftypes.INT16 ftypes.INT24, ftypes.INT32, ftypes.INT64, ftypes.FLOAT, ftypes.DOUBLE, ftypes.ABSOLUTE_TIME ftypes.RELATIVE_TIME, ftypes.STRING, ftypes.STRINGZ, ftypes.UINT_STRING, ftypes.ETHER, ftypes.BYTES ftypes.UINT_BYTES, ftypes.IPv4, ftypes.IPv6, ftypes.IPXNET, ftypes.FRAMENUM, ftypes.PCRE, ftypes.GUID ftypes.OID, ftypes.EUI64
--  voidstring (optional) : A VoidString object. 
--  base (optional) : The representation: one of base.NONE, base.DEC, base.HEX, base.OCT, base.DEC_HEX, base.HEX_DEC 
--  mask (optional) : The bitmask to be used. 
--  descr (optional) : The description of the field. 

--     FLAGS Field 정의
--     bit data를 다루기 위해서는, unit8() 함수의 마지막에 bits mask 값을 기재합니다.
f.ver        = ProtoField.uint8("tpcstream.ver",       "VERSION",   base.DEC, nil, 0xC0) -- 0xC0 (16) = 1100 0000 (2)
f.reserved   = ProtoField.uint8("tpcstream.reserved",  "RESERVED",  base.HEX, nil, 0x30) -- 0x30 (16) = 0011 0000 (2)
f.encrypted  = ProtoField.uint8("tpcstream.encrypted", "ENCRYPTED", base.DEC, nil, 0x08) -- 0x08 (16) = 0000 1000 (2)
f.iframe     = ProtoField.uint8("tpcstream.iframe",    "I-FRAME",   base.DEC, nil, 0x04) -- 0x04 (16) = 0000 0100 (2)
f.startframe = ProtoField.uint8("tpcstream.start",     "START",     base.DEC, nil, 0x02) -- 0x02 (16) = 0000 0010 (2)
f.endframe   = ProtoField.uint8("tpcstream.end",       "END",       base.DEC, nil, 0x01) -- 0x01 (16) = 0000 0001 (2)

--   HEADER Fields for START BIT == 1 
--        Frame Size Field 정의
f.frame_size = ProtoField.uint32("tpcstream.frame_size", "FRAME_SIZE", base.DEC)

--     Frame Count Field 정의
f.frame_count = ProtoField.uint32("tpcstream.frame_count", "FRAME_COUNT", base.DEC)

--   HEADER Fields for START BIT == 0
--       Packet Count Field 정의
f.packet_count = ProtoField.uint16("tpcstream.packet_count", "PACKET_COUNT", base.DEC)

--   BODY : Frame Data
f.frame_data = ProtoField.bytes("tpcstream.frame_data", "FRAME_DATA")


----------------------------------------------
-- (3) p_tpcstream 객체의 dissector() 함수를 정의합니다.
-- tpcstream dissector function
function p_tpcstream.dissector(buffer, pinfo, tree)

  -- validate packet length is adequate, otherwise quit
  if buffer:len() == 0 then return end

  ---------------------------------------------------------
  -- [A] 패킷 상세정보 창에 SubTree 추가하기
  ---------------------------------------------------------
  subtree = tree:add(p_tpcstream, buffer(0))
  
    -- treeitem:add(proto_field [,tvbrange] [,value [,text1 [,text2] ...] ])
    --   Adds a ProtoField, containing the specified packet detail, as a new TreeItem child to the current TreeItem
    -- https://wiki.wireshark.org/LuaAPI/TreeItem

  -- STARTCODE 값 Parsing. 
  -- buffer의 첫번째 byte(0)부터 4byte만큼을 startcode field에 적용하여 추가합니다.
  subtree:add(f.startcode, buffer(0, 4)) 
  -- buffer 는 'big endian' 입니다. litte endian 으로 추가하려면 add_le() 사용
  
  -- FLAGS 값 Parsing. 
  -- buffer의 다섯번째 byte부터 1byte만큼을 읽고, 이를 ver, reserved, encrypted.. 등 
  -- 위에서 정의한 각 bit field에 적용하여 추가합니다.
  local flags = buffer(4, 1)
  -- add flags bit
  subtree:add(f.ver, flags)
  subtree:add(f.reserved, flags)
  subtree:add(f.encrypted, flags)
  subtree:add(f.iframe, flags)
  subtree:add(f.startframe, flags)
  subtree:add(f.endframe, flags)

  -- "start" bit flag 값에 따라 패킷의 형태가 다르므로, 먼저 start bit flag 값을 읽습니다.
  local startbit = buffer(4, 1):bitfield(6, 1)

  -- start bit 값이 1이냐 0이냐에 따라 추가해야 하는 subtree 항목이 달라집니다.
  if startbit == 1 then
    -- start bit 값이 1이면, frame size, frame count, frame data 항목을 추가합니다.
    subtree:add(f.frame_size, buffer(5, 3))
    subtree:add(f.frame_count, buffer(8, 4))
    --subtree:add(f.frame_data, buffer(16))
    -- 다음과 같은 방법으로 다른 Dissector를 불러와 사용할 수 있습니다.
    -- TOAST PC Streaming Protocol의 frame data는 H.264 패킷을 담고 있으므로, 
    -- 아래와 같이 H.264 Protocol Dissector를 불러와 frame data를 Parsing 합니다.
    h264_table = Dissector.get("h264")
    tvb = buffer(16)
    h264_table:call(tvb:tvb(), pinfo, tree)
  else 
    -- start bit 값이 0이면, frame count, packet count, frame data 항목을 추가합니다.
    subtree:add(f.frame_count, buffer(5, 4))
    subtree:add(f.packet_count, buffer(9, 2))
    --subtree:add(f.frame_data, buffer(12))
    h264_table = Dissector.get("h264")
    tvb = buffer(12)
    h264_table:call(tvb:tvb(), pinfo, tree)
  end
  ---------------------------------------------------------

  ---------------------------------------------------------
  -- [B] 패킷 목록 표시창 info 컬럼에 표시될 정보 
  ---------------------------------------------------------
  -- Protocol 컬럼에 표시될 프로토콜 이름 지정
  -- "TPCSTREAM" 으로 설정
  pinfo.cols.protocol = p_tpcstream.name

  -- Info 컬럼에 표시될 프로토콜 정보 문자열 생성
  -- 본 예제에서는 다음과 같은 형태로 출력하도록 작성합니다.
  -- * start bit가 1인 패킷
  --    [프레임 타입] frame count #프레임카운트 start
  -- * end bit가 1인 패킷
  --     frame count #프레임카운트 end seq=#패킷카운트 
  -- * start/end bit가 모두 1인 패킷
  --    [프레임 타입] frame count #프레임카운트 start, end
  -- * 나머지
  --     frame count #프레임카운트 cont. seq=#패킷카운트
  local info_str = "";
  -- 버전 정보 출력
  info_str = info_str.."VER="..version.." "

  local endbit = buffer(4, 1):bitfield(7, 1)
  if startbit == 1 then
    -- start bit가 1이면, I/P Frame 여부와 frame count값, start/end 여부 출력
    local iframe = buffer(4, 1):bitfield(5, 1)
    if iframe == 1 then
      info_str = info_str.."[I-FRAME]"
    else 
     info_str = info_str.."[P-FRAME]"
    end

    local frame_count = buffer(8, 4):uint()
    info_str = info_str.." frame count "..frame_count.." start"
    if endbit == 1 then
      info_str = info_str..", end"
    end
  else
    -- start bit가 0이면, frame count, packet count 값과 continue/end 여부 출력
    local frame_count = buffer(5, 4):uint()
    local packet_count = buffer(9, 2):uint()
    info_str = info_str.." frame count "..frame_count
    if endbit == 1 then 
      info_str = info_str.." end "
    else
      info_str = info_str.." cont. "
    end

    info_str = info_str.."seq="..packet_count
  end

  -- 생성한 문자열을 Info 컬럼 값으로 설정
  pinfo.cols.info = info_str
  --------------------------------------------------------
end


----------------------------------------------
-- (4) Initialization routine : p_tpcstream의 init() 함수를 정의합니다.
-- 이름 그대로 초기화 시 호출되는 함수입니다.
-- 본 예제에서는 특별히 처리할 것이 없으므로 비워둡니다.
function p_tpcstream.init()
end

----------------------------------------------
-- (5) UDP Port 7010, 8010번을 통해 전송되는 패킷은 이 Dissector를 적용하도록 설정합니다.
local udp_dissector_table = DissectorTable.get("udp.port") 
udp_dissector_table:add(7010, p_tpcstream) --
udp_dissector_table:add(8010, p_tpcstream)

------------------------------------------------
-- (6) Wireshark의 init.lua 에 다음을 추가한 뒤, wireshark 를 구동.
--
-- dofile("D:\\tools\\tpcstream.lua")

-----------------------------------------------
-- wireshark 에서 사용되는 lua api 정보는 https://wiki.wireshark.org/LuaAPI 참조
