-- ============================================
-- VORTEX BYPASS - DORONG LUCKY BLOCK
-- Fitur: Push Power 1B/detik + Auto x2 Money
-- ============================================

local player = game.Players.LocalPlayer
local runService = game:GetService("RunService")
local replicatedStorage = game:GetService("ReplicatedStorage")
local players = game:GetService("Players")

-- ===== KONFIGURASI =====
local TARGET_POWER = 1e9 -- 1B per push
local AUTO_X2_MONEY = true
local AUTO_PUSH_INTERVAL = 0.05 -- 20 push/detik = 20B/detik

-- ===== GUI =====
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexBypass"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 350, 0, 280)
mainFrame.Position = UDim2.new(0.5, -175, 0.5, -140)
mainFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
mainFrame.BackgroundTransparency = 0.15
mainFrame.BorderSizePixel = 2
mainFrame.BorderColor3 = Color3.fromRGB(255, 50, 50)
mainFrame.Active = true
mainFrame.Draggable = true
mainFrame.Parent = screenGui

-- Close
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0, 28, 0, 28)
closeBtn.Position = UDim2.new(1, -33, 0, 5)
closeBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 0)
closeBtn.Text = "✕"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.TextSize = 16
closeBtn.Font = Enum.Font.SourceSansBold
closeBtn.Parent = mainFrame
closeBtn.MouseButton1Click:Connect(function() screenGui.Enabled = false end)

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.Position = UDim2.new(0, 0, 0, 8)
title.BackgroundTransparency = 1
title.Text = "🔥 VORTEX BYPASS"
title.TextColor3 = Color3.fromRGB(255, 50, 50)
title.TextSize = 24
title.Font = Enum.Font.SourceSansBold
title.Parent = mainFrame

-- Status
local statusLabel = Instance.new("TextLabel")
statusLabel.Size = UDim2.new(1, 0, 0, 28)
statusLabel.Position = UDim2.new(0, 0, 0, 52)
statusLabel.BackgroundTransparency = 1
statusLabel.Text = "⚡ STATUS: READY"
statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
statusLabel.TextSize = 15
statusLabel.Font = Enum.Font.SourceSans
statusLabel.Parent = mainFrame

-- Push Power display
local pushLabel = Instance.new("TextLabel")
pushLabel.Size = UDim2.new(1, 0, 0, 30)
pushLabel.Position = UDim2.new(0, 0, 0, 82)
pushLabel.BackgroundTransparency = 1
pushLabel.Text = "💪 Push Power: --"
pushLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
pushLabel.TextSize = 16
pushLabel.Font = Enum.Font.SourceSans
pushLabel.Parent = mainFrame

-- Money display
local moneyLabel = Instance.new("TextLabel")
moneyLabel.Size = UDim2.new(1, 0, 0, 30)
moneyLabel.Position = UDim2.new(0, 0, 0, 112)
moneyLabel.BackgroundTransparency = 1
moneyLabel.Text = "💰 Money: --"
moneyLabel.TextColor3 = Color3.fromRGB(255, 215, 0)
moneyLabel.TextSize = 16
moneyLabel.Font = Enum.Font.SourceSans
moneyLabel.Parent = mainFrame

-- Tombol START
local startBtn = Instance.new("TextButton")
startBtn.Size = UDim2.new(0.8, 0, 0, 50)
startBtn.Position = UDim2.new(0.1, 0, 0, 152)
startBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 50)
startBtn.Text = "🚀 START BYPASS"
startBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
startBtn.TextSize = 20
startBtn.Font = Enum.Font.SourceSansBold
startBtn.Parent = mainFrame

-- Auto x2 toggle
local x2Btn = Instance.new("TextButton")
x2Btn.Size = UDim2.new(0.35, 0, 0, 35)
x2Btn.Position = UDim2.new(0.1, 0, 0, 210)
x2Btn.BackgroundColor3 = Color3.fromRGB(0, 150, 0)
x2Btn.Text = "✅ x2 ON"
x2Btn.TextColor3 = Color3.fromRGB(255, 255, 255)
x2Btn.TextSize = 14
x2Btn.Font = Enum.Font.SourceSansBold
x2Btn.Parent = mainFrame

-- Toggle button
local toggleBtn = Instance.new("TextButton")
toggleBtn.Size = UDim2.new(0, 100, 0, 35)
toggleBtn.Position = UDim2.new(0.02, 0, 0.92, 0)
toggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleBtn.Text = "🔥 VORTEX"
toggleBtn.TextColor3 = Color3.fromRGB(255, 50, 50)
toggleBtn.TextSize = 16
toggleBtn.Font = Enum.Font.SourceSansBold
toggleBtn.Parent = screenGui
toggleBtn.MouseButton1Click:Connect(function() screenGui.Enabled = not screenGui.Enabled end)

-- ===== ENGINE =====

-- Cari semua nilai power
local function findPowerValues()
    local found = {}
    
    -- Cari di leaderstats
    local ls = player:FindFirstChild("leaderstats")
    if ls then
        for _, v in pairs(ls:GetChildren()) do
            if v:IsA("NumberValue") or v:IsA("IntValue") then
                table.insert(found, v)
            end
        end
    end
    
    -- Cari di player
    for _, v in pairs(player:GetChildren()) do
        if v:IsA("NumberValue") or v:IsA("IntValue") then
            table.insert(found, v)
        end
        if v:IsA("Folder") or v:IsA("Model") then
            for _, child in pairs(v:GetChildren()) do
                if child:IsA("NumberValue") or child:IsA("IntValue") then
                    table.insert(found, child)
                end
            end
        end
    end
    
    return found
end

-- Cari remote event untuk push
local function findPushRemote()
    for _, v in pairs(replicatedStorage:GetDescendants()) do
        if v:IsA("RemoteEvent") then
            local name = v.Name:lower()
            if name:find("push") or name:find("click") or name:find("interact") or name:find("block") then
                return v
            end
        end
    end
    return nil
end

-- Cari money value
local function findMoneyValue()
    local ls = player:FindFirstChild("leaderstats")
    if ls then
        for _, v in pairs(ls:GetChildren()) do
            local name = v.Name:lower()
            if name:find("money") or name:find("cash") or name:find("coin") or name:find("gold") then
                return v
            end
        end
    end
    for _, v in pairs(player:GetChildren()) do
        local name = v.Name:lower()
        if name:find("money") or name:find("cash") or name:find("coin") then
            if v:IsA("NumberValue") or v:IsA("IntValue") then
                return v
            end
        end
    end
    return nil
end

-- Hook ke fungsi push
local function hookPushFunction()
    for _, obj in pairs(game:GetDescendants()) do
        if obj:IsA("ModuleScript") then
            pcall(function()
                local module = require(obj)
                if type(module) == "table" then
                    for key, value in pairs(module) do
                        if type(value) == "function" then
                            local funcName = tostring(key):lower()
                            if funcName:find("push") or funcName:find("click") or funcName:find("interact") then
                                rawset(module, key, function(...)
                                    local args = {...}
                                    for i, arg in pairs(args) do
                                        if type(arg) == "number" and arg > 1000 then
                                            args[i] = arg * 1000000 -- Multiply
                                        end
                                    end
                                    return value(unpack(args))
                                end)
                            end
                        end
                    end
                end
            end)
        end
    end
end

-- MAIN BYPASS
local function bypassPush()
    local success = false
    
    -- Method 1: Inject ke semua NumberValue
    local values = findPowerValues()
    for _, v in pairs(values) do
        local name = v.Name:lower()
        if name:find("power") or name:find("push") or name:find("point") or name:find("score") then
            pcall(function()
                v.Value = v.Value + TARGET_POWER
                success = true
            end)
        end
    end
    
    -- Method 2: Kirim remote event
    local remote = findPushRemote()
    if remote then
        pcall(function()
            remote:FireServer(TARGET_POWER)
            remote:FireServer("push", TARGET_POWER)
            remote:FireServer("click", TARGET_POWER)
            success = true
        end)
    end
    
    -- Method 3: Cari dan klik tombol push di UI
    for _, obj in pairs(player.PlayerGui:GetDescendants()) do
        if obj:IsA("TextButton") then
            local text = obj.Text or ""
            if text:find("PUSH") or text:find("Push") or text:find("Dorong") then
                pcall(function()
                    obj:Activate()
                    success = true
                end)
            end
        end
    end
    
    return success
end

-- Auto x2 Money
local function enableX2Money()
    if not AUTO_X2_MONEY then return end
    
    local money = findMoneyValue()
    if money then
        pcall(function()
            -- Double the money value
            money.Value = money.Value * 2
            moneyLabel.Text = "💰 Money: " .. string.format("%.2f", money.Value)
        end)
    end
    
    -- Cari tombol x2 di UI dan klik
    for _, obj in pairs(player.PlayerGui:GetDescendants()) do
        if obj:IsA("TextButton") then
            local text = obj.Text or ""
            if text:find("x2") or text:find("X2") or text:find("2x") then
                pcall(function()
                    obj:Activate()
                end)
            end
        end
    end
end

-- LOOP BYPASS
local bypassRunning = false
local pushCount = 0

local function startBypass()
    if bypassRunning then return end
    bypassRunning = true
    startBtn.Text = "⏳ RUNNING..."
    startBtn.BackgroundColor3 = Color3.fromRGB(255, 150, 0)
    statusLabel.Text = "⚡ BYPASS ACTIVE"
    statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    
    -- Hook functions
    hookPushFunction()
    
    task.spawn(function()
        while bypassRunning do
            -- Push Power +1B
            local pushed = bypassPush()
            if pushed then
                pushCount = pushCount + 1
                pushLabel.Text = "💪 Push Power: +" .. string.format("%.0fB", TARGET_POWER/1e9 * pushCount)
            end
            
            -- Auto x2 Money
            if AUTO_X2_MONEY then
                enableX2Money()
            end
            
            task.wait(AUTO_PUSH_INTERVAL)
        end
    end)
end

local function stopBypass()
    bypassRunning = false
    startBtn.Text = "🚀 START BYPASS"
    startBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 50)
    statusLabel.Text = "⏹️ STOPPED"
    statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
end

-- ===== BUTTON EVENTS =====
startBtn.MouseButton1Click:Connect(function()
    if bypassRunning then
        stopBypass()
    else
        startBypass()
    end
end)

x2Btn.MouseButton1Click:Connect(function()
    AUTO_X2_MONEY = not AUTO_X2_MONEY
    if AUTO_X2_MONEY then
        x2Btn.Text = "✅ x2 ON"
        x2Btn.BackgroundColor3 = Color3.fromRGB(0, 150, 0)
    else
        x2Btn.Text = "❌ x2 OFF"
        x2Btn.BackgroundColor3 = Color3.fromRGB(150, 0, 0)
    end
end)

-- ===== AUTO START (bisa di-uncomment) =====
-- task.wait(1)
-- startBypass()

print("🔥 VORTEX BYPASS LOADED!")
print("💪 Push Power: 1B per push")
print("💰 Auto x2 Money: ON")
print("⚡ Klik START untuk memulai")
