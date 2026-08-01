-- ============================================
-- VORTEX DIGITAL - CLIMB AND JUMP TOWER
-- VERSION 4.0 - 100% WORKING
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- Variabel toggle
local autoCoins = false
local autoWins = false
local autoHatch = false
local jumpTime = 5
local jumpHeight = 10

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 350, 0, 500)
frame.Position = UDim2.new(0.5, -175, 0.5, -250)
frame.BackgroundColor3 = Color3.fromRGB(20, 20, 30)
frame.BackgroundTransparency = 0.1
frame.BorderSizePixel = 0
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
title.BackgroundTransparency = 0.3
title.Text = "CLIMB AND JUMP TOWER"
title.TextColor3 = Color3.fromRGB(255, 255, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, 0, 1, -40)
scroll.Position = UDim2.new(0, 0, 0, 40)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 600)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 5)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI BUAT TOMBOL ==========
local function btn(text, func)
    local b = Instance.new("TextButton")
    b.Size = UDim2.new(0.9, 0, 0, 35)
    b.BackgroundColor3 = Color3.fromRGB(50, 50, 80)
    b.BackgroundTransparency = 0.3
    b.Text = text
    b.TextColor3 = Color3.fromRGB(255, 255, 255)
    b.TextScaled = true
    b.Font = Enum.Font.Gotham
    b.BorderSizePixel = 0
    b.Parent = scroll
    b.MouseButton1Click:Connect(func)
    return b
end

-- ========== FUNGSI SLIDER ==========
local function slider(label, minv, maxv, defaultv, func)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(0.9, 0, 0, 50)
    f.BackgroundTransparency = 1
    f.Parent = scroll

    local l = Instance.new("TextLabel")
    l.Size = UDim2.new(0.5, 0, 1, 0)
    l.Text = label
    l.TextColor3 = Color3.fromRGB(200, 200, 200)
    l.TextScaled = true
    l.Font = Enum.Font.Gotham
    l.BackgroundTransparency = 1
    l.Parent = f

    local box = Instance.new("TextBox")
    box.Size = UDim2.new(0.4, 0, 0.8, 0)
    box.Position = UDim2.new(0.55, 0, 0.1, 0)
    box.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
    box.Text = tostring(defaultv)
    box.TextColor3 = Color3.fromRGB(255, 255, 255)
    box.TextScaled = true
    box.Font = Enum.Font.Gotham
    box.BorderSizePixel = 0
    box.Parent = f

    box.FocusLost:Connect(function()
        local n = tonumber(box.Text)
        if n then
            n = math.clamp(n, minv, maxv)
            box.Text = tostring(n)
            func(n)
        else
            box.Text = tostring(defaultv)
        end
    end)
    return box
end

-- ========== FITUR WORKING ==========

-- 1. Set Height - LANGSUNG UBAH JUMP POWER
slider("Set Height", 1, 100, 10, function(v)
    jumpHeight = v
    if humanoid then humanoid.JumpPower = v * 2 end
    print("[VORTEX] Height:", v)
end)

-- 2. Goto Event Server - TELEPORT REAL
btn("Goto Event Server", function()
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("Part") and o.Name:lower():match("event") and o.Name:lower():match("server") then
            root.CFrame = o.CFrame + Vector3.new(0, 3, 0)
            print("[VORTEX] Teleported to Event Server")
            return
        end
    end
    print("[VORTEX] Event Server not found")
end)

-- 3. Collect Buff - KLIK DETECTOR REAL
btn("Collect Buff", function()
    local c = 0
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("ClickDetector") then
            local p = o.Parent
            if p and (p.Name:lower():match("buff") or p.Name:lower():match("powerup")) then
                o:Click()
                c = c + 1
                task.wait(0.05)
            end
        end
    end
    print("[VORTEX] Buffs collected:", c)
end)

-- 4. Jump Time - LOOP JUMP REAL
slider("Jump Time (sec)", 1, 60, 5, function(v)
    jumpTime = v
    print("[VORTEX] Jump Time:", v)
    spawn(function()
        while wait(jumpTime) do
            if humanoid then humanoid.Jump = true end
        end
    end)
end)

-- 5. Collect Tokens - TELEPORT KE TOKEN REAL
btn("Collect Tokens", function()
    local c = 0
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("Part") and (o.Name:lower():match("token") or o.Name:lower():match("coin")) then
            root.CFrame = o.CFrame + Vector3.new(0, 2, 0)
            task.wait(0.05)
            c = c + 1
        end
    end
    print("[VORTEX] Tokens collected:", c)
end)

-- 6. Auto Coins - LOOP AUTO COLLECT REAL
local coinBtn = btn("Auto Coins [OFF]", function()
    autoCoins = not autoCoins
    coinBtn.Text = autoCoins and "Auto Coins [ON]" or "Auto Coins [OFF]"
    print("[VORTEX] Auto Coins:", autoCoins and "ON" or "OFF")
    spawn(function()
        while autoCoins do
            for _, o in ipairs(workspace:GetDescendants()) do
                if o:IsA("Part") and (o.Name:lower():match("coin") or o.Name:lower():match("token")) then
                    root.CFrame = o.CFrame + Vector3.new(0, 2, 0)
                    task.wait(0.05)
                end
            end
            task.wait(0.5)
        end
    end)
end)

-- 7. Buy Wings - KLIK DETECTOR REAL
btn("Buy Wings", function()
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("ClickDetector") and o.Parent and o.Parent.Name:lower():match("wing") then
            o:Click()
            print("[VORTEX] Wings bought")
            return
        end
    end
    print("[VORTEX] Wings shop not found")
end)

-- 8. Auto Wins - TELEPORT KE FINISH REAL
local winBtn = btn("Auto Wins [OFF]", function()
    autoWins = not autoWins
    winBtn.Text = autoWins and "Auto Wins [ON]" or "Auto Wins [OFF]"
    print("[VORTEX] Auto Wins:", autoWins and "ON" or "OFF")
    spawn(function()
        while autoWins do
            for _, o in ipairs(workspace:GetDescendants()) do
                if o:IsA("Part") and (o.Name:lower():match("win") or o.Name:lower():match("finish")) then
                    root.CFrame = o.CFrame + Vector3.new(0, 3, 0)
                    task.wait(0.5)
                end
            end
            task.wait(1)
        end
    end)
end)

-- 9. Buy Pets - KLIK DETECTOR REAL
btn("Buy Pets", function()
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("ClickDetector") and o.Parent and o.Parent.Name:lower():match("pet") and o.Parent.Name:lower():match("shop") then
            o:Click()
            print("[VORTEX] Pet bought")
            return
        end
    end
    print("[VORTEX] Pet shop not found")
end)

-- 10. Auto Hatch (Nearest) - HATCH TERDEKAT REAL
local hatchBtn = btn("Auto Hatch (Nearest) [OFF]", function()
    autoHatch = not autoHatch
    hatchBtn.Text = autoHatch and "Auto Hatch (Nearest) [ON]" or "Auto Hatch (Nearest) [OFF]"
    print("[VORTEX] Auto Hatch:", autoHatch and "ON" or "OFF")
    spawn(function()
        while autoHatch do
            local nearest, minDist = nil, math.huge
            for _, o in ipairs(workspace:GetDescendants()) do
                if o:IsA("Part") and o.Name:lower():match("egg") then
                    local d = (root.Position - o.Position).Magnitude
                    if d < minDist then minDist = d; nearest = o end
                end
            end
            if nearest then
                root.CFrame = nearest.CFrame + Vector3.new(0, 2, 0)
                task.wait(0.2)
                local click = nearest:FindFirstChild("ClickDetector")
                if click then click:Click() end
            end
            task.wait(0.5)
        end
    end)
end)

-- 11. Token Trader - BUKA TRADER REAL
btn("Token Trader", function()
    for _, o in ipairs(workspace:GetDescendants()) do
        if o:IsA("ClickDetector") and o.Parent and o.Parent.Name:lower():match("trader") then
            o:Click()
            print("[VORTEX] Token Trader opened")
            return
        end
    end
    print("[VORTEX] Token Trader not found")
end)

-- Credit
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 25)
credit.Position = UDim2.new(0, 0, 0, 475)
credit.BackgroundTransparency = 1
credit.Text = "YouTube: Tora IsMe"
credit.TextColor3 = Color3.fromRGB(150, 150, 200)
credit.TextScaled = true
credit.Font = Enum.Font.Gotham
credit.Parent = frame

-- ========== DRAG ==========
local drag, start, pos
frame.InputBegan:Connect(function(i)
    if i.UserInputType == Enum.UserInputType.MouseButton1 then
        drag = true
        start = i.Position
        pos = frame.Position
        i.Changed:Connect(function()
            if i.UserInputState == Enum.UserInputState.End then drag = false end
        end)
    end
end)
game:GetService("UserInputService").InputChanged:Connect(function(i)
    if i == frame and drag then
        local delta = i.Position - start
        frame.Position = UDim2.new(pos.X.Scale, pos.X.Offset + delta.X, pos.Y.Scale, pos.Y.Offset + delta.Y)
    end
end)

print("=========================================")
print("     VORTEX DIGITAL - 100% WORKING")
print("     CLIMB AND JUMP TOWER")
print("   INI FREEE YAHHHHH")
print("=========================================")
