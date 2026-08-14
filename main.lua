-- VORTEX COIN THROWER ULTIMATE GUI - RAPIH & MODERN
-- By VORTEX DIGITAL AI

local Players = game:GetService("Players")
local player = Players.LocalPlayer
local gui = Instance.new("ScreenGui")
gui.Name = "VortexThrowGUI"
gui.Parent = player:WaitForChild("PlayerGui")

-- MAIN FRAME
local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 500, 0, 580)
frame.Position = UDim2.new(0.5, -250, 0.5, -290)
frame.BackgroundColor3 = Color3.fromRGB(8, 8, 28)
frame.BackgroundTransparency = 0.08
frame.BorderSizePixel = 0
frame.Parent = gui

local mainCorner = Instance.new("UICorner")
mainCorner.CornerRadius = UDim.new(0, 16)
mainCorner.Parent = frame

-- SHADOW
local shadow = Instance.new("Frame")
shadow.Size = UDim2.new(1, 0, 1, 0)
shadow.Position = UDim2.new(0, 4, 0, 4)
shadow.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
shadow.BackgroundTransparency = 0.6
shadow.BorderSizePixel = 0
shadow.ZIndex = 0
shadow.Parent = frame
local shadowCorner = Instance.new("UICorner")
shadowCorner.CornerRadius = UDim.new(0, 16)
shadowCorner.Parent = shadow

-- HEADER
local header = Instance.new("Frame")
header.Size = UDim2.new(1, 0, 0, 55)
header.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
header.BorderSizePixel = 0
header.Parent = frame
local headerCorner = Instance.new("UICorner")
headerCorner.CornerRadius = UDim.new(0, 16)
headerCorner.Parent = header

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 1, 0)
title.BackgroundTransparency = 1
title.Text = "🌀 VORTEX COIN THROWER"
title.TextColor3 = Color3.fromRGB(0, 220, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = header

local subTitle = Instance.new("TextLabel")
subTitle.Size = UDim2.new(1, 0, 0, 20)
subTitle.Position = UDim2.new(0, 0, 1, -20)
subTitle.BackgroundTransparency = 1
subTitle.Text = "✦ FULL UNLOCK ✦"
subTitle.TextColor3 = Color3.fromRGB(255, 200, 50)
subTitle.TextScaled = true
subTitle.Font = Enum.Font.GothamMedium
subTitle.Parent = header

-- DIVIDER LINE
local divider = Instance.new("Frame")
divider.Size = UDim2.new(0.92, 0, 0, 2)
divider.Position = UDim2.new(0.04, 0, 0.12, 0)
divider.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
divider.BackgroundTransparency = 0.5
divider.BorderSizePixel = 0
divider.Parent = frame

-- SECTION LABEL MAIN
local mainLabel = Instance.new("TextLabel")
mainLabel.Size = UDim2.new(0.92, 0, 0, 25)
mainLabel.Position = UDim2.new(0.04, 0, 0.15, 0)
mainLabel.BackgroundTransparency = 1
mainLabel.Text = "⚡ MAIN FEATURES"
mainLabel.TextColor3 = Color3.fromRGB(0, 200, 255)
mainLabel.TextScaled = true
mainLabel.Font = Enum.Font.GothamBold
mainLabel.TextXAlignment = Enum.TextXAlignment.Left
mainLabel.Parent = frame

-- ACTIVATE BUTTON (FULL WIDTH)
local mainBtn = Instance.new("TextButton")
mainBtn.Size = UDim2.new(0.92, 0, 0, 40)
mainBtn.Position = UDim2.new(0.04, 0, 0.22, 0)
mainBtn.BackgroundColor3 = Color3.fromRGB(0, 120, 220)
mainBtn.Text = "▶ ACTIVATE VORTEX ENGINE"
mainBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
mainBtn.Font = Enum.Font.GothamBold
mainBtn.TextScaled = true
mainBtn.Parent = frame
local btnCorner = Instance.new("UICorner")
btnCorner.CornerRadius = UDim.new(0, 10)
btnCorner.Parent = mainBtn

local active = false
mainBtn.MouseButton1Click:Connect(function()
    active = not active
    mainBtn.Text = active and "⏹ ENGINE ACTIVE" or "▶ ACTIVATE VORTEX ENGINE"
    mainBtn.BackgroundColor3 = active and Color3.fromRGB(220, 40, 40) or Color3.fromRGB(0, 120, 220)
end)

-- VARIABLES UNTUK STATUS FITUR
local autoThrowActive = false
local speedActive = false

-- GRID MAIN (2 KOLOM)
local function createGridButton(text, icon, yPos, color, callback)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.44, 0, 0, 38)
    btn.Position = UDim2.new(0.04, 0, yPos, 0)
    btn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
    btn.Text = "❌ " .. icon .. " " .. text
    btn.TextColor3 = color or Color3.fromRGB(220, 220, 255)
    btn.Font = Enum.Font.GothamMedium
    btn.TextScaled = true
    btn.Parent = frame
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, 8)
    c.Parent = btn
    
    local activeState = false
    btn.MouseButton1Click:Connect(function()
        activeState = not activeState
        btn.Text = activeState and "✅ " .. icon .. " " .. text or "❌ " .. icon .. " " .. text
        btn.BackgroundColor3 = activeState and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(18, 18, 45)
        if callback then callback(activeState, btn) end
    end)
    return btn
end

local yBase = 0.30

-- Auto Throw
local autoBtn = createGridButton("Auto Throw", "🎯", yBase, Color3.fromRGB(100, 255, 150), function(state)
    autoThrowActive = state
end)
autoBtn.Position = UDim2.new(0.04, 0, yBase, 0)

-- VIP Unlock (khusus tombol sekali tekan)
local vipBtn = Instance.new("TextButton")
vipBtn.Size = UDim2.new(0.44, 0, 0, 38)
vipBtn.Position = UDim2.new(0.52, 0, yBase, 0)
vipBtn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
vipBtn.Text = "👑 VIP Unlock"
vipBtn.TextColor3 = Color3.fromRGB(255, 215, 0)
vipBtn.Font = Enum.Font.GothamMedium
vipBtn.TextScaled = true
vipBtn.Parent = frame
local vipCorner = Instance.new("UICorner")
vipCorner.CornerRadius = UDim.new(0, 8)
vipCorner.Parent = vipBtn

vipBtn.MouseButton1Click:Connect(function()
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("BoolValue") and string.lower(v.Name):find("vip") then v.Value = true end
        if v:IsA("NumberValue") and string.lower(v.Name):find("vip") then v.Value = 999999 end
    end
    vipBtn.Text = "✅ VIP UNLOCKED"
    vipBtn.BackgroundColor3 = Color3.fromRGB(0, 180, 50)
    task.wait(1.5)
    vipBtn.Text = "👑 VIP Unlock"
    vipBtn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
end)

-- Speed Throw
local spdBtn = createGridButton("Speed Throw", "⚡", yBase + 0.075, Color3.fromRGB(255, 255, 100), function(state)
    speedActive = state
    if state then
        game:GetService("RunService").RenderStepped:Connect(function()
            if not speedActive then return end
            for _, v in pairs(game:GetDescendants()) do
                if v:IsA("NumberValue") and string.lower(v.Name):find("cooldown") then
                    v.Value = 0.01
                end
            end
        end)
    end
end)
spdBtn.Position = UDim2.new(0.04, 0, yBase + 0.075, 0)

-- x5 Luck (khusus tombol sekali tekan)
local luckBtn = Instance.new("TextButton")
luckBtn.Size = UDim2.new(0.44, 0, 0, 38)
luckBtn.Position = UDim2.new(0.52, 0, yBase + 0.075, 0)
luckBtn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
luckBtn.Text = "🍀 x5 Luck"
luckBtn.TextColor3 = Color3.fromRGB(0, 255, 200)
luckBtn.Font = Enum.Font.GothamMedium
luckBtn.TextScaled = true
luckBtn.Parent = frame
local luckCorner = Instance.new("UICorner")
luckCorner.CornerRadius = UDim.new(0, 8)
luckCorner.Parent = luckBtn

luckBtn.MouseButton1Click:Connect(function()
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("NumberValue") and string.lower(v.Name):find("luck") then v.Value = v.Value * 5 end
        if v:IsA("NumberValue") and string.lower(v.Name):find("chance") then v.Value = math.min(v.Value * 3, 100) end
    end
    luckBtn.Text = "✅ x5 APPLIED"
    luckBtn.BackgroundColor3 = Color3.fromRGB(0, 180, 50)
    task.wait(1.2)
    luckBtn.Text = "🍀 x5 Luck"
    luckBtn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
end)

-- DIVIDER 2
local divider2 = Instance.new("Frame")
divider2.Size = UDim2.new(0.92, 0, 0, 2)
divider2.Position = UDim2.new(0.04, 0, 0.50, 0)
divider2.BackgroundColor3 = Color3.fromRGB(255, 200, 50)
divider2.BackgroundTransparency = 0.5
divider2.BorderSizePixel = 0
divider2.Parent = frame

-- SHOP SECTION
local shopLabel = Instance.new("TextLabel")
shopLabel.Size = UDim2.new(0.92, 0, 0, 25)
shopLabel.Position = UDim2.new(0.04, 0, 0.535, 0)
shopLabel.BackgroundTransparency = 1
shopLabel.Text = "🛒 SHOP CONTROL"
shopLabel.TextColor3 = Color3.fromRGB(255, 200, 50)
shopLabel.TextScaled = true
shopLabel.Font = Enum.Font.GothamBold
shopLabel.TextXAlignment = Enum.TextXAlignment.Left
shopLabel.Parent = frame

-- Auto Sell (Full Width) dengan toggle ✅/❌
local sellBtn = Instance.new("TextButton")
sellBtn.Size = UDim2.new(0.92, 0, 0, 38)
sellBtn.Position = UDim2.new(0.04, 0, 0.60, 0)
sellBtn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
sellBtn.Text = "❌ 💰 Auto Sell All"
sellBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
sellBtn.Font = Enum.Font.GothamMedium
sellBtn.TextScaled = true
sellBtn.Parent = frame
local sellCorner = Instance.new("UICorner")
sellCorner.CornerRadius = UDim.new(0, 10)
sellCorner.Parent = sellBtn

local sellActive = false
sellBtn.MouseButton1Click:Connect(function()
    sellActive = not sellActive
    sellBtn.Text = sellActive and "✅ 💰 Auto Sell ON" or "❌ 💰 Auto Sell All"
    sellBtn.BackgroundColor3 = sellActive and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(18, 18, 45)
    if sellActive then
        task.spawn(function()
            while sellActive do
                for _, v in pairs(player:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("coin") then
                        v.Value = v.Value + 1000
                    end
                end
                task.wait(0.5)
            end
        end)
    end
end)

-- SHOP GRID (3 KOLOM) - Tombol sekali tekan
local function createShopButton(text, icon, xPos, yPos, color, upgradeKey)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.28, 0, 0, 38)
    btn.Position = UDim2.new(xPos, 0, yPos, 0)
    btn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
    btn.Text = icon .. " " .. text
    btn.TextColor3 = color or Color3.fromRGB(220, 220, 255)
    btn.Font = Enum.Font.GothamMedium
    btn.TextScaled = true
    btn.Parent = frame
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, 8)
    c.Parent = btn
    
    btn.MouseButton1Click:Connect(function()
        for _, v in pairs(game:GetDescendants()) do
            if v:IsA("NumberValue") and string.lower(v.Name):find(upgradeKey) then
                v.Value = v.Value * 2
            end
        end
        btn.Text = "✅ " .. icon .. " UP!"
        btn.BackgroundColor3 = Color3.fromRGB(0, 100, 50)
        task.wait(0.8)
        btn.Text = icon .. " " .. text
        btn.BackgroundColor3 = Color3.fromRGB(18, 18, 45)
    end)
    return btn
end

local shopY = 0.68

-- Upgrade Luck
local upLuck = createShopButton("Luck", "🔮", 0.04, shopY, Color3.fromRGB(150, 200, 255), "luckmult")

-- Upgrade Value
local upVal = createShopButton("Value", "💎", 0.36, shopY, Color3.fromRGB(255, 215, 100), "valuemult")

-- Upgrade Speed
local upSpd = createShopButton("Speed", "🚀", 0.68, shopY, Color3.fromRGB(100, 255, 255), "speedmult")

-- CLOSE BUTTON
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0.25, 0, 0, 35)
closeBtn.Position = UDim2.new(0.375, 0, 0.86, 0)
closeBtn.BackgroundColor3 = Color3.fromRGB(80, 80, 80)
closeBtn.Text = "✕ CLOSE"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.Font = Enum.Font.GothamBold
closeBtn.TextScaled = true
closeBtn.Parent = frame
local closeCorner = Instance.new("UICorner")
closeCorner.CornerRadius = UDim.new(0, 10)
closeCorner.Parent = closeBtn

closeBtn.MouseButton1Click:Connect(function()
    gui:Destroy()
end)

-- DRAG SYSTEM
local drag = false
local dragStartPos, startMousePos

header.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 then
        drag = true
        startMousePos = input.Position
        dragStartPos = frame.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                drag = false
            end
        end)
    end
end)

game:GetService("UserInputService").InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement and drag then
        local delta = input.Position - startMousePos
        frame.Position = UDim2.new(dragStartPos.X.Scale, dragStartPos.X.Offset + delta.X, dragStartPos.Y.Scale, dragStartPos.Y.Offset + delta.Y)
    end
end)

print("🌀 VORTEX COIN THROWER - RAPIH + TOGGLE ✅/❌ LOADED")
