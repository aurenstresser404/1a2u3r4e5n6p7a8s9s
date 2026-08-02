-- ============================================
-- VORTEX CLIMB & JUMP TOWER - NO KEY SYSTEM
-- LANGSUNG JALAN TANPA VERIFIKASI
-- TELEGRAM : @realvortexdigital
-- ============================================

-- Jalankan script utama dari GitHub
local function runMainScript()
    local Games = loadstring(game:HttpGet("https://raw.githubusercontent.com/gumanba/Scripts/refs/heads/main/ClimbandJump", true))()
    if Games then
        for PlaceID, Execute in pairs(Games) do
            if PlaceID == game.PlaceId then
                loadstring(game:HttpGet(Execute))()
                print("[VORTEX] Script loaded for Place ID: " .. game.PlaceId)
                return
            end
        end
        print("[VORTEX] No matching Place ID found. Running fallback...")
        -- Fallback: jalankan langsung jika tidak ada match
        loadstring(game:HttpGet("https://raw.githubusercontent.com/gumanba/Scripts/refs/heads/main/ClimbandJump", true))()
    else
        print("[VORTEX] Failed to load script from GitHub")
    end
end

-- Jalankan langsung
runMainScript()

print("=========================================")
print("     VORTEX CLIMB & JUMP TOWER")
print("     NO KEY SYSTEM - LANGSUNG JALAN")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
