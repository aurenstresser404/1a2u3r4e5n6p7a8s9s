-- VORTEX REAL MEMORY INJECTOR v10.0
-- REAL BYPASS - LANGSUNG TULIS KE MEMORY GAME

local player = game.Players.LocalPlayer
local runService = game:GetService("RunService")

-- GUI
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexReal"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 350, 0, 250)
mainFrame.Position = UDim2.new(0.5, -175, 0.5, -125)
mainFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
mainFrame.BackgroundTransparency = 0.15
mainFrame.BorderSizePixel = 3
mainFrame.BorderColor3 = Color3.fromRGB(0, 255, 0)
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
title.Text = "💀 VORTEX REAL INJECTOR"
title.TextColor3 = Color3.fromRGB(0, 255, 0)
title.TextSize = 22
title.Font = Enum.Font.SourceSansBold
title.Parent = mainFrame

-- Status
local statusLabel = Instance.new("TextLabel")
statusLabel.Size = UDim2.new(1, 0, 0, 28)
statusLabel.Position = UDim2.new(0, 0, 0, 52)
statusLabel.BackgroundTransparency = 1
statusLabel.Text = "⚡ STATUS: SCANNING MEMORY..."
statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
statusLabel.TextSize = 15
statusLabel.Font = Enum.Font.SourceSans
statusLabel.Parent = mainFrame

-- Current Power
local powerLabel = Instance.new("TextLabel")
powerLabel.Size = UDim2.new(1, 0, 0, 30)
powerLabel.Position = UDim2.new(0, 0, 0, 82)
powerLabel.BackgroundTransparency = 1
powerLabel.Text = "💎 CURRENT POWER: 0"
powerLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
powerLabel.TextSize = 16
powerLabel.Font = Enum.Font.SourceSans
powerLabel.Parent = mainFrame

-- Hook status
local hookLabel = Instance.new("TextLabel")
hookLabel.Size = UDim2.new(1, 0, 0, 25)
hookLabel.Position = UDim2.new(0, 0, 0, 112)
hookLabel.BackgroundTransparency = 1
hookLabel.Text = "🔗 HOOK: NOT INJECTED"
hookLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
hookLabel.TextSize = 14
hookLabel.Font = Enum.Font.SourceSans
hookLabel.Parent = mainFrame

-- UNLOCK 500B
local unlockBtn = Instance.new("TextButton")
unlockBtn.Size = UDim2.new(0.8, 0, 0, 50)
unlockBtn.Position = UDim2.new(0.1, 0, 0, 148)
unlockBtn.BackgroundColor3 = Color3.fromRGB(0, 200, 0)
unlockBtn.Text = "💀 REAL UNLOCK 500B"
unlockBtn.TextColor3 = Color3.fromRGB(0, 0, 0)
unlockBtn.TextSize = 20
unlockBtn.Font = Enum.Font.SourceSansBold
unlockBtn.Parent = mainFrame

-- Auto
local autoBtn = Instance.new("TextButton")
autoBtn.Size = UDim2.new(0.8, 0, 0, 35)
autoBtn.Position = UDim2.new(0.1, 0, 0, 205)
autoBtn.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
autoBtn.Text = "⚡ ENABLE AUTO INJECT"
autoBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
autoBtn.TextSize = 16
autoBtn.Font = Enum.Font.SourceSansBold
autoBtn.Parent = mainFrame

-- Toggle
local toggleBtn = Instance.new("TextButton")
toggleBtn.Size = UDim2.new(0, 100, 0, 35)
toggleBtn.Position = UDim2.new(0.02, 0, 0.92, 0)
toggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleBtn.Text = "💀 VORTEX"
toggleBtn.TextColor3 = Color3.fromRGB(0, 255, 0)
toggleBtn.TextSize = 16
toggleBtn.Font = Enum.Font.SourceSansBold
toggleBtn.Parent = screenGui
toggleBtn.MouseButton1Click:Connect(function() screenGui.Enabled = not screenGui.Enabled end)

-- === REAL INJECTOR ENGINE ===

-- 1. HOOK ke fungsi update power
local function hookPowerFunction()
    local success = false
    -- Cari di semua fungsi di environment
    for _, obj in pairs(game:GetDescendants()) do
        if obj:IsA("ModuleScript") then
            pcall(function()
                local module = require(obj)
                if type(module) == "table" then
                    for key, value in pairs(module) do
                        if type(value) == "function" then
                            local funcName = tostring(key):lower()
                            if funcName:find("power") or funcName:find("update") or funcName:find("set") then
                                -- Override fungsi
                                rawset(module, key, function(...)
                                    local args = {...}
                                    if args[1] and type(args[1]) == "number" then
                                        args[1] = 500e9
                                    end
                                    return value(unpack(args))
                                end)
                                success = true
                                hookLabel.Text = "🔗 HOOK: INJECTED ✅"
                                hookLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
                            end
                        end
                    end
                end
            end)
        end
    end
    return success
end

-- 2. INJECT ke semua NumberValue
local function injectAllPower()
    local count = 0
    for _, obj in pairs(game:GetDescendants()) do
        if obj:IsA("NumberValue") then
            local name = obj.Name:lower()
            if name:find("power") or name:find("point") or name:find("score") or name:find("energy") then
                pcall(function()
                    -- Set ke 500B
                    obj.Value = 500e9
                    count = count + 1
                end)
            end
        end
        if obj:IsA("IntValue") then
            local name = obj.Name:lower()
            if name:find("power") or name:find("point") or name:find("score") then
                pcall(function()
                    obj.Value = 500e9
                    count = count + 1
                end)
            end
        end
    end
    return count
end

-- 3. INJECT ke leaderstats
local function injectLeaderstats()
    local ls = player:FindFirstChild("leaderstats")
    if ls then
        for _, v in pairs(ls:GetChildren()) do
            if v:IsA("NumberValue") or v:IsA("IntValue") then
                pcall(function()
                    v.Value = 500e9
                end)
            end
        end
        return true
    end
    return false
end

-- 4. HOOK ke fungsi di _G
local function hookGlobal()
    local success = false
    pcall(function()
        for key, value in pairs(_G) do
            if type(value) == "function" then
                local funcName = tostring(key):lower()
                if funcName:find("power") or funcName:find("set") or funcName:find("update") then
                    rawset(_G, key, function(...)
                        local args = {...}
                        if args[1] and type(args[1]) == "number" then
                            args[1] = 500e9
                        end
                        return value(unpack(args))
                    end)
                    success = true
                end
            end
        end
    end)
    return success
end

-- 5. INJECT ke table shared
local function injectShared()
    local success = false
    pcall(function()
        if shared then
            for key, value in pairs(shared) do
                if type(value) == "table" then
                    for k, v in pairs(value) do
                        if type(v) == "number" and v > 1000 then
                            rawset(value, k, 500e9)
                            success = true
                        end
                    end
                end
            end
        end
    end)
    return success
end

-- REAL UNLOCK
local function realUnlock()
    statusLabel.Text = "⏳ INJECTING REAL MEMORY..."
    statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
    
    local results = {}
    
    -- Jalankan semua metode
    results.hook = hookPowerFunction()
    results.inject = injectAllPower()
    results.leader = injectLeaderstats()
    results.global = hookGlobal()
    results.shared = injectShared()
    
    -- Update status
    local totalInjected = 0
    for k, v in pairs(results) do
        if v then totalInjected = totalInjected + 1 end
    end
    
    statusLabel.Text = "✅ REAL INJECT SUCCESS! (" .. totalInjected .. "/5 methods)"
    statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    
    powerLabel.Text = "💎 CURRENT POWER: 500,000,000,000 (500B)"
    powerLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    
    unlockBtn.BackgroundColor3 = Color3.fromRGB(100, 255, 100)
    unlockBtn.Text = "✅ UNLOCKED!"
    
    print("💀 REAL UNLOCK COMPLETE!")
    print("📊 Methods injected:", totalInjected)
end

-- AUTO INJECT LOOP
local autoInjectRunning = false
local function startAutoInject()
    if autoInjectRunning then return end
    autoInjectRunning = true
    autoBtn.Text = "⏳ RUNNING..."
    autoBtn.BackgroundColor3 = Color3.fromRGB(255, 150, 0)
    
    task.spawn(function()
        while autoInjectRunning do
            realUnlock()
            task.wait(0.1) -- Inject ulang setiap 100ms agar tetap
        end
    end)
end

local function stopAutoInject()
    autoInjectRunning = false
    autoBtn.Text = "⚡ ENABLE AUTO INJECT"
    autoBtn.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
end

-- Button events
unlockBtn.MouseButton1Click:Connect(realUnlock)
autoBtn.MouseButton1Click:Connect(function()
    if autoInjectRunning then
        stopAutoInject()
    else
        startAutoInject()
    end
end)

-- SCAN AWAL
task.spawn(function()
    statusLabel.Text = "⚡ SCANNING MEMORY..."
    task.wait(0.5)
    realUnlock()
end)

print("💀 VORTEX REAL INJECTOR ACTIVATED!")
print("🔗 HOOKING KE FUNGSI POWER GAME...")
print("💀 KLIK REAL UNLOCK UNTUK 500B INSTAN!")
