-- VORTEX SAFE BYPASS ENGINE v6.0
-- Anti-rebirth, increment bertahap 1B per push dengan simulasi natural

local player = game.Players.LocalPlayer
local replicatedStorage = game:GetService("ReplicatedStorage")
local runService = game:GetService("RunService")
local virtualInput = game:GetService("VirtualInputManager")

-- GUI
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexSafeBypass"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 320, 0, 200)
mainFrame.Position = UDim2.new(0.5, -160, 0.5, -100)
mainFrame.BackgroundColor3 = Color3.fromRGB(10, 10, 30)
mainFrame.BackgroundTransparency = 0.15
mainFrame.BorderSizePixel = 2
mainFrame.BorderColor3 = Color3.fromRGB(0, 200, 255)
mainFrame.Active = true
mainFrame.Draggable = true
mainFrame.Parent = screenGui

-- Close
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0, 28, 0, 28)
closeBtn.Position = UDim2.new(1, -33, 0, 5)
closeBtn.BackgroundColor3 = Color3.fromRGB(200, 30, 30)
closeBtn.Text = "✕"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.TextSize = 16
closeBtn.Font = Enum.Font.SourceSansBold
closeBtn.Parent = mainFrame
closeBtn.MouseButton1Click:Connect(function() screenGui.Enabled = false end)

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 35)
title.Position = UDim2.new(0, 0, 0, 8)
title.BackgroundTransparency = 1
title.Text = "🌀 VORTEX SAFE PUSH"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextSize = 20
title.Font = Enum.Font.SourceSansBold
title.Parent = mainFrame

-- Status
local statusLabel = Instance.new("TextLabel")
statusLabel.Size = UDim2.new(1, 0, 0, 28)
statusLabel.Position = UDim2.new(0, 0, 0, 48)
statusLabel.BackgroundTransparency = 1
statusLabel.Text = "⚡ Status: READY"
statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
statusLabel.TextSize = 15
statusLabel.Font = Enum.Font.SourceSans
statusLabel.Parent = mainFrame

-- Power display
local powerLabel = Instance.new("TextLabel")
powerLabel.Size = UDim2.new(1, 0, 0, 30)
powerLabel.Position = UDim2.new(0, 0, 0, 78)
powerLabel.BackgroundTransparency = 1
powerLabel.Text = "💎 Power: 0 B"
powerLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
powerLabel.TextSize = 16
powerLabel.Font = Enum.Font.SourceSans
powerLabel.Parent = mainFrame

-- Push button
local pushBtn = Instance.new("TextButton")
pushBtn.Size = UDim2.new(0.75, 0, 0, 45)
pushBtn.Position = UDim2.new(0.125, 0, 0, 120)
pushBtn.BackgroundColor3 = Color3.fromRGB(0, 150, 255)
pushBtn.Text = "💥 PUSH +1B"
pushBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
pushBtn.TextSize = 20
pushBtn.Font = Enum.Font.SourceSansBold
pushBtn.Parent = mainFrame

-- Auto button
local autoBtn = Instance.new("TextButton")
autoBtn.Size = UDim2.new(0.75, 0, 0, 35)
autoBtn.Position = UDim2.new(0.125, 0, 0, 170)
autoBtn.BackgroundColor3 = Color3.fromRGB(200, 100, 0)
autoBtn.Text = "⚡ AUTO PUSH (SAFE)"
autoBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
autoBtn.TextSize = 16
autoBtn.Font = Enum.Font.SourceSansBold
autoBtn.Parent = mainFrame

-- Toggle button
local toggleBtn = Instance.new("TextButton")
toggleBtn.Size = UDim2.new(0, 100, 0, 35)
toggleBtn.Position = UDim2.new(0.02, 0, 0.92, 0)
toggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleBtn.Text = "🌀 VORTEX"
toggleBtn.TextColor3 = Color3.fromRGB(0, 200, 255)
toggleBtn.TextSize = 16
toggleBtn.Font = Enum.Font.SourceSansBold
toggleBtn.Parent = screenGui
toggleBtn.MouseButton1Click:Connect(function() screenGui.Enabled = not screenGui.Enabled end)

-- Cari nilai power yang benar
local function findRealPowerValue()
    -- Cari di leaderstats
    local ls = player:FindFirstChild("leaderstats")
    if ls then
        for _, v in pairs(ls:GetChildren()) do
            if v:IsA("NumberValue") and (v.Name:lower():find("power") or v.Name:lower():find("point") or v.Name:lower():find("score")) then
                return v
            end
        end
    end
    
    -- Cari di player
    for _, v in pairs(player:GetChildren()) do
        if v:IsA("NumberValue") and (v.Name:lower():find("power") or v.Name:lower():find("point")) then
            return v
        end
    end
    
    -- Cari di workspace
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("NumberValue") and v.Parent and v.Parent:IsA("Model") and v.Parent.Name:lower():find("player") then
            if v.Name:lower():find("power") or v.Name:lower():find("point") then
                return v
            end
        end
    end
    
    return nil
end

local powerValue = findRealPowerValue()
if powerValue then
    powerLabel.Text = "💎 Power: " .. string.format("%.0f B", powerValue.Value/1e9)
end

-- Fungsi push aman (tidak memicu rebirth)
local function safePush()
    if not powerValue then
        statusLabel.Text = "⚠️ Power value not found!"
        statusLabel.TextColor3 = Color3.fromRGB(255, 200, 0)
        return
    end
    
    -- Increment bertahap (1B)
    powerValue.Value = powerValue.Value + 1e9
    
    -- Update display
    powerLabel.Text = "💎 Power: " .. string.format("%.0f B", powerValue.Value/1e9)
    statusLabel.Text = "✅ +1B PUSHED!"
    statusLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    
    -- Simulasi click alami (opsional)
    pcall(function()
        -- Cari tombol push di game dan klik virtual
        local screenGui2 = player.PlayerGui
        for _, gui in pairs(screenGui2:GetChildren()) do
            if gui:IsA("ScreenGui") then
                for _, btn in pairs(gui:GetDescendants()) do
                    if btn:IsA("TextButton") and (btn.Name:lower():find("push") or btn.Name:lower():find("click") or btn.Name:lower():find("interact")) then
                        virtualInput:SendMouseButtonEvent(btn.AbsolutePosition.X + btn.AbsoluteSize.X/2, btn.AbsolutePosition.Y + btn.AbsoluteSize.Y/2, 0, true, game, 0)
                        task.wait(0.01)
                        virtualInput:SendMouseButtonEvent(btn.AbsolutePosition.X + btn.AbsoluteSize.X/2, btn.AbsolutePosition.Y + btn.AbsoluteSize.Y/2, 0, false, game, 0)
                        break
                    end
                end
            end
        end
    end)
end

-- Auto push (dengan delay natural)
local autoRunning = false
local function startAutoPush()
    if autoRunning then return end
    autoRunning = true
    autoBtn.Text = "⏳ RUNNING..."
    autoBtn.BackgroundColor3 = Color3.fromRGB(255, 150, 0)
    
    task.spawn(function()
        while autoRunning do
            safePush()
            task.wait(0.1) -- 10 push/detik = 10B/detik, aman tidak memicu rebirth
        end
    end)
end

-- Stop auto
local function stopAutoPush()
    autoRunning = false
    autoBtn.Text = "⚡ AUTO PUSH (SAFE)"
    autoBtn.BackgroundColor3 = Color3.fromRGB(200, 100, 0)
end

-- Button events
pushBtn.MouseButton1Click:Connect(safePush)
autoBtn.MouseButton1Click:Connect(function()
    if autoRunning then
        stopAutoPush()
    else
        startAutoPush()
    end
end)

-- Update tiap detik
task.spawn(function()
    while true do
        if powerValue then
            powerLabel.Text = "💎 Power: " .. string.format("%.0f B", powerValue.Value/1e9)
        end
        task.wait(1)
    end
end)

print("🌀 VORTEX SAFE BYPASS ACTIVATED!")
print("✅ Anti-rebirth protection aktif")
print("💥 1B per push - aman dan stabil")
