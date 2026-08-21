-- VORTEX INSTANT 500B POWER UNLOCKER v8.0
-- LANGSUNG SET POWER KE 500B TANPA PROSES

local player = game.Players.LocalPlayer

-- CARI SEMUA NILAI POWER
local function findPowerValues()
    local found = {}
    
    -- Cari di seluruh game
    for _, obj in pairs(game:GetDescendants()) do
        if obj:IsA("NumberValue") then
            local name = obj.Name:lower()
            -- Cari semua yang berhubungan dengan power
            if name:find("power") or name:find("point") or name:find("score") or name:find("energy") or name:find("stat") then
                table.insert(found, obj)
            end
        end
        -- Cari juga IntValue
        if obj:IsA("IntValue") then
            local name = obj.Name:lower()
            if name:find("power") or name:find("point") or name:find("score") then
                table.insert(found, obj)
            end
        end
    end
    
    return found
end

-- GUI UNLOCK
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexUnlocker"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 400, 0, 300)
mainFrame.Position = UDim2.new(0.5, -200, 0.5, -150)
mainFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
mainFrame.BackgroundTransparency = 0.2
mainFrame.BorderSizePixel = 3
mainFrame.BorderColor3 = Color3.fromRGB(255, 215, 0)
mainFrame.Active = true
mainFrame.Draggable = true
mainFrame.Parent = screenGui

-- Close
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0, 30, 0, 30)
closeBtn.Position = UDim2.new(1, -35, 0, 5)
closeBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 0)
closeBtn.Text = "✕"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.TextSize = 18
closeBtn.Font = Enum.Font.SourceSansBold
closeBtn.Parent = mainFrame
closeBtn.MouseButton1Click:Connect(function() screenGui.Enabled = false end)

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 50)
title.Position = UDim2.new(0, 0, 0, 10)
title.BackgroundTransparency = 1
title.Text = "⚡ VORTEX POWER UNLOCKER"
title.TextColor3 = Color3.fromRGB(255, 215, 0)
title.TextSize = 26
title.Font = Enum.Font.SourceSansBold
title.Parent = mainFrame

-- Subtitle
local subTitle = Instance.new("TextLabel")
subTitle.Size = UDim2.new(1, 0, 0, 30)
subTitle.Position = UDim2.new(0, 0, 0, 60)
subTitle.BackgroundTransparency = 1
subTitle.Text = "SET 500B POWER INSTAN"
subTitle.TextColor3 = Color3.fromRGB(255, 100, 100)
subTitle.TextSize = 18
subTitle.Font = Enum.Font.SourceSans
subTitle.Parent = mainFrame

-- Status
local statusLabel = Instance.new("TextLabel")
statusLabel.Size = UDim2.new(1, 0, 0, 30)
statusLabel.Position = UDim2.new(0, 0, 0, 95)
statusLabel.BackgroundTransparency = 1
statusLabel.Text = "🔍 SCANNING POWER VALUES..."
statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
statusLabel.TextSize = 16
statusLabel.Font = Enum.Font.SourceSans
statusLabel.Parent = mainFrame

-- Found count
local countLabel = Instance.new("TextLabel")
countLabel.Size = UDim2.new(1, 0, 0, 25)
countLabel.Position = UDim2.new(0, 0, 0, 125)
countLabel.BackgroundTransparency = 1
countLabel.Text = "Found: 0 values"
countLabel.TextColor3 = Color3.fromRGB(200, 200, 200)
countLabel.TextSize = 14
countLabel.Font = Enum.Font.SourceSans
countLabel.Parent = mainFrame

-- Tombol UNLOCK 500B
local unlockBtn = Instance.new("TextButton")
unlockBtn.Size = UDim2.new(0.8, 0, 0, 60)
unlockBtn.Position = UDim2.new(0.1, 0, 0, 165)
unlockBtn.BackgroundColor3 = Color3.fromRGB(255, 50, 50)
unlockBtn.Text = "🚀 UNLOCK 500B POWER"
unlockBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
unlockBtn.TextSize = 24
unlockBtn.Font = Enum.Font.SourceSansBold
unlockBtn.Parent = mainFrame

-- Tombol RESET ke 0
local resetBtn = Instance.new("TextButton")
resetBtn.Size = UDim2.new(0.35, 0, 0, 35)
resetBtn.Position = UDim2.new(0.1, 0, 0, 235)
resetBtn.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
resetBtn.Text = "↺ RESET"
resetBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
resetBtn.TextSize = 16
resetBtn.Font = Enum.Font.SourceSansBold
resetBtn.Parent = mainFrame

-- Tombol TOGGLE
local toggleBtn = Instance.new("TextButton")
toggleBtn.Size = UDim2.new(0, 120, 0, 40)
toggleBtn.Position = UDim2.new(0.02, 0, 0.9, 0)
toggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleBtn.Text = "⚡ VORTEX"
toggleBtn.TextColor3 = Color3.fromRGB(255, 215, 0)
toggleBtn.TextSize = 18
toggleBtn.Font = Enum.Font.SourceSansBold
toggleBtn.Parent = screenGui
toggleBtn.MouseButton1Click:Connect(function()
    screenGui.Enabled = not screenGui.Enabled
end)

-- FIND ALL POWER VALUES
local allPowerValues = {}

local function scanAllPower()
    allPowerValues = findPowerValues()
    countLabel.Text = "Found: " .. #allPowerValues .. " power values"
    if #allPowerValues > 0 then
        statusLabel.Text = "✅ " .. #allPowerValues .. " VALUES FOUND! READY TO UNLOCK"
        statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
        return true
    else
        statusLabel.Text = "⚠️ NO POWER VALUES FOUND! RETRYING..."
        statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
        return false
    end
end

-- UNLOCK 500B
local function unlock500B()
    -- Scan ulang
    allPowerValues = findPowerValues()
    
    if #allPowerValues == 0 then
        statusLabel.Text = "❌ NO VALUES FOUND! CAN'T UNLOCK"
        statusLabel.TextColor3 = Color3.fromRGB(255, 0, 0)
        return
    end
    
    local count = 0
    for _, val in pairs(allPowerValues) do
        pcall(function()
            local oldVal = val.Value
            val.Value = 500e9 -- 500B
            count = count + 1
            print("✅ SET:", val.Name, oldVal, "→", val.Value)
        end)
    end
    
    statusLabel.Text = "🎯 500B UNLOCKED! (" .. count .. " values modified)"
    statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    unlockBtn.BackgroundColor3 = Color3.fromRGB(0, 200, 100)
    unlockBtn.Text = "✅ UNLOCKED!"
    
    -- Cek apakah power push juga berubah
    for _, val in pairs(allPowerValues) do
        if val.Name:lower():find("push") then
            print("💪 PUSH POWER:", val.Value)
        end
    end
end

-- RESET ke 0
local function resetPower()
    allPowerValues = findPowerValues()
    for _, val in pairs(allPowerValues) do
        pcall(function()
            val.Value = 0
        end)
    end
    statusLabel.Text = "↺ RESET TO 0"
    statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
    unlockBtn.BackgroundColor3 = Color3.fromRGB(255, 50, 50)
    unlockBtn.Text = "🚀 UNLOCK 500B POWER"
end

-- Button events
unlockBtn.MouseButton1Click:Connect(unlock500B)
resetBtn.MouseButton1Click:Connect(resetPower)

-- SCAN AWAL
task.spawn(function()
    scanAllPower()
    -- Scan ulang tiap 5 detik
    while true do
        task.wait(5)
        scanAllPower()
    end
end)

print("⚡ VORTEX POWER UNLOCKER ACTIVATED!")
print("🔍 SCANNING ALL POWER VALUES...")
print("💀 KLIK UNLOCK UNTUK SET 500B INSTAN!")
