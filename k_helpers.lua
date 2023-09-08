--[[---------------------------]]--
-- k_helpers.lua
-- a collection of useful functions
-- to enhance KumoMTA
--[[---------------------------]]--



-----------------------------------------------------------------------
--[[ Local Function printTableF() ]]--
-- Used to pretty print any sized table in Lua
-- but in this case it writes to an external file
-- This could be resource intensive so only use it for debugging
-------------------------------------------------------------------------
function k_printTableF( filename, t )
    local fh = io.open(filename,"a")
    local printTable_cache = {}

    local function sub_printTable( t, indent, filename )

        if ( printTable_cache[tostring(t)] ) then
            fh:write( indent .. "*" .. tostring(t) )
            fh:write("\n")
        else
            printTable_cache[tostring(t)] = true
            if ( type( t ) == "table" ) then
                for pos,val in pairs( t ) do
                    if ( type(val) == "table" ) then
                        fh:write( indent .. "[" .. pos .. "] => " .. tostring( t ).. " {" )
                        fh:write("\n")
                        sub_printTable( val, indent .. string.rep( " ", string.len(pos)+8 ), filename )
                        fh:write( indent .. string.rep( " ", string.len(pos)+6 ) .. "}" )
                        fh:write("\n")
                elseif ( type(val) == "string" ) then
                        fh:write( indent .. "[" .. pos .. '] => "' .. val .. '"' )
                        fh:write("\n")
                    else
                        fh:write( indent .. "[" .. pos .. "] => " .. tostring(val) )
                        fh:write("\n")
                    end
                end
            else
                fh:write( indent..tostring(t) )
                fh:write("\n")
            end
        end
    end

    if ( type(t) == "table" ) then
        fh:write( tostring(t) .. " {" )
        fh:write("\n")
        sub_printTable( t, "  ", filename )
        fh:write( "}" )
        fh:write("\n")
    else
        sub_printTable( t, "  ",filename )
    end
    fh:write("\n")
    fh:close()

end

-- function isempty()

function isempty(s)
    return s == nil or s == ''
end

-- function set_tenant_by_X()
function set_tenant_by_X(headername)
  local headers = message:get_all_headers()
  local tenant = "default"
  if headers[headername] == high then
    tenant = "priority"
  end
  return tenant
end

-- function k_print(fname,text)
function k_print(fname,text)
  fh = io.open(fname,"a")
  fh:write(text)
  fh:close()
end




