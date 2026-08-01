-- ============================================
-- VORTEX DIGITAL - ULTRA WORK VERSION
-- Speed Walk | Auto Coin | Auto Piala | Auto Buy Pet | Auto Unlock Worlds
-- SEMUA FITUR BISA ON/OFF
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- Variabel toggle
local speedOn = false
local speedVal = 50
local coinOn = false
local pialaOn = false
local petOn = false
local unlockOn = false

-- Buat GUI
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 300, 0, 420)
frame.Position = UDim2.new(0.5, -150, 0.5, -210)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 20)
frame.BackgroundTransparency = 0.1
frame.BorderSizePixel = 0
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.BackgroundColor3 = Color3.fromRGB(25, 25, 45)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, 0, 1, -40)
scroll.Position = UDim2.new(0, 0, 0, 40)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 400)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 6)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- Fungsi buat tombol toggle
local function makeToggle(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.9, 0, 0, 38)
    btn.BackgroundColor3 = Color3.fromRGB(35, 35, 60)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.GothamBold
    btn.BorderSizePixel = 0
    btn.Parent = scroll
    btn.MouseButton1Click:Connect(function()
        local new = not getter()
        setter(new)
        btn.Text = text .. (new and " [ON]" or " [OFF]")
        btn.BackgroundColor3 = new and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(35, 35, 60)
        print("[VORTEX] " .. text .. ": " .. (new and "ON" or "OFF"))
    end)
    return btn
end

-- Fungsi slider
local function makeSlider(label, minv, maxv, defaultv, callback)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(0.9, 0, 0, 40)
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
    box.Size = UDim2.new(0.35, 0, 0.8, 0)
    box.Position = UDim2.new(0.6, 0, 0.1, 0)
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
            callback(n)
        else
            box.Text = tostring(defaultv)
        end
    end)
    return box
end

-- ========== FITUR 1: SPEED WALK ==========
makeSlider("Speed Walk", 16, 250, 50, function(v)
    speedVal = v
    if speedOn and humanoid then humanoid.WalkSpeed = v end
end)

makeToggle("Speed Walk", function() return speedOn end, function(v)
    speedOn = v
    if v then
        humanoid.WalkSpeed = speedVal
    else
        humanoid.WalkSpeed = 16
    end
end)

-- ========== FITUR 2: AUTO COIN ==========
makeToggle("Auto Coin", function() return coinOn end, function(v)
    coinOn = v
    spawn(function()
        while coinOn do
            local ls = player:FindFirstChild("leaderstats")
            if ls then
                for _, s in ipairs(ls:GetChildren()) do
                    if s:IsA("IntValue") or s:IsA("NumberValue") then
                        if s.Value > 0 and s.Value < 999999999 then
                            s.Value = s.Value * 2
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 3: AUTO PIALA ==========
makeToggle("Auto Piala", function() return pialaOn end, function(v)
    pialaOn = v
    spawn(function()
        while pialaOn do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") then
                    local n = obj.Name:lower()
                    if n:match("trophy") or n:match("piala") or n:match("cup") or n:match("medal") then
                        local target = obj:IsA("Part") and obj or obj:FindFirstChild("HumanoidRootPart") or obj:FindFirstChild("Part")
                        if target and root then
                            root.CFrame = target.CFrame + Vector3.new(0, 2, 0)
                            wait(0.05)
                            local click = obj:FindFirstChild("ClickDetector")
                            if click then click:Click() end
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 4: AUTO BUY PET ==========
makeToggle("Auto Buy Pet", function() return petOn end, function(v)
    petOn = v
    spawn(function()
        while petOn do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("pet") or name:match("egg") or name:match("gacha") or name:match("shop") then
                            if obj:IsA("ClickDetector") then
                                obj:Click()
                            elseif obj:IsA("ProximityPrompt") then
                                obj:InputHoldStart()
                                wait(0.1)
                                obj:InputHoldEnd()
                            end
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 5: AUTO UNLOCK WORLDS ==========
makeToggle("Auto Unlock Worlds", function() return unlockOn end, function(v)
    unlockOn = v
    spawn(function()
        while unlockOn do
            -- Cari tombol di GUI
            for _, g in ipairs(player.PlayerGui:GetDescendants()) do
                if g:IsA("TextButton") then
                    local txt = g.Text:lower()
                    if txt:match("unlock") or txt:match("buy") or txt:match("next") then
                        if txt:match("world") or txt:match("level") or txt:match("stage") then
                            g:Click()
                            wait(0.2)
                        end
                    end
                end
            end
            -- Cari ClickDetector
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("unlock") or name:match("world") or name:match("gate") or name:match("portal") then
                            obj:Click()
                            wait(0.2)
                        end
                    end
                end
            end
            -- Naikkan level di leaderstats
            local ls = player:FindFirstChild("leaderstats")
            if ls then
                for _, s in ipairs(ls:GetChildren()) do
                    if s:IsA("IntValue") and (s.Name:lower():match("level") or s.Name:lower():match("stage")) then
                        s.Value = s.Value + 50
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 25)
credit.Position = UDim2.new(0, 0, 0, 385)
credit.BackgroundTransparency = 1
credit.Text = "TELEGRAM : @realvortexdigital"
credit.TextColor3 = Color3.fromRGB(0, 200, 255)
credit.TextScaled = true
credit.Font = Enum.Font.GothamBold
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
print("     VORTEX DIGITAL - ULTRA WORK")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
