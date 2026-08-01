-- ============================================
-- VORTEX DIGITAL - SUPER AUTO COMPLETE
-- Auto Clicker | +1 Muscle | x2 Power | Rebirth | Auto Collect | Auto Upgrade | Auto Pet
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")
local mouse = player:GetMouse()

-- ========== VARIABEL TOGGLE ==========
local autoClicker = false
local autoMuscle = false
local autoPower = false
local autoRebirth = false
local autoCollect = false
local autoUpgrade = false
local autoPet = false
local clickSpeed = 0.1

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexSuperGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 350, 0, 550)
frame.Position = UDim2.new(0.5, -175, 0.5, -275)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 20)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL - SUPER AUTO"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -45)
scroll.Position = UDim2.new(0, 5, 0, 42)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 550)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 5)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI TOMBOL ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, 0, 0, 38)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.GothamBold
    btn.BorderSizePixel = 1
    btn.BorderColor3 = Color3.fromRGB(0, 100, 200)
    btn.Parent = scroll
    btn.MouseButton1Click:Connect(function()
        local newState = not getter()
        setter(newState)
        btn.Text = text .. (newState and " [ON]" or " [OFF]")
        btn.BackgroundColor3 = newState and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
        print("[VORTEX] " .. text .. ": " .. (newState and "ON" or "OFF"))
    end)
    return btn
end

-- ========== SLIDER ==========
local function sliderInput(label, minv, maxv, defaultv, callback)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(1, 0, 0, 38)
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

-- ========== FITUR 1: AUTO CLICKER ==========
sliderInput("Click Speed (detik)", 0.01, 1, 0.1, function(v)
    clickSpeed = v
    print("[VORTEX] Click speed: " .. v .. " detik")
end)

toggleButton("Auto Clicker", function() return autoClicker end, function(v)
    autoClicker = v
    spawn(function()
        while autoClicker do
            -- Simulasi klik kiri
            mouse1click()
            -- Klik kanan juga
            mouse1click()
            wait(clickSpeed)
        end
    end)
end)

-- ========== FITUR 2: +1 MUSCLE / AUTO BREAK ==========
toggleButton("+1 Muscle / Auto Break", function() return autoMuscle end, function(v)
    autoMuscle = v
    spawn(function()
        while autoMuscle do
            -- Cari tombol "Muscle" atau "Break" atau "Train"
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("muscle") or txt:match("break") or txt:match("train") or txt:match("punch") then
                        btn:Click()
                        wait(0.1)
                    end
                end
            end
            -- Cari ClickDetector
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("muscle") or name:match("break") or name:match("train") then
                            obj:Click()
                            wait(0.1)
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 3: x2 POWER ==========
toggleButton("x2 Power", function() return autoPower end, function(v)
    autoPower = v
    spawn(function()
        while autoPower do
            -- Cari tombol "Power" atau "x2" atau "Boost"
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("power") or txt:match("x2") or txt:match("boost") or txt:match("strength") then
                        btn:Click()
                        wait(0.1)
                    end
                end
            end
            -- Gandakan nilai Power di leaderstats
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        local name = stat.Name:lower()
                        if name:match("power") or name:match("strength") or name:match("attack") or name:match("damage") then
                            if stat.Value < 999999999 then
                                stat.Value = stat.Value * 2
                                print("[VORTEX] Power doubled: " .. stat.Value)
                            end
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 4: AUTO REBIRTH ==========
toggleButton("Auto Rebirth", function() return autoRebirth end, function(v)
    autoRebirth = v
    spawn(function()
        while autoRebirth do
            -- Cari tombol "Rebirth" atau "Prestige" atau "Reset"
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("rebirth") or txt:match("prestige") or txt:match("reset") or txt:match("ascend") then
                        btn:Click()
                        print("[VORTEX] Rebirth triggered!")
                        wait(0.5)
                    end
                end
            end
            -- Cari ClickDetector rebirth
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("rebirth") or name:match("prestige") or name:match("ascend") then
                            obj:Click()
                            print("[VORTEX] Rebirth triggered!")
                            wait(0.5)
                        end
                    end
                end
            end
            wait(1)
        end
    end)
end)

-- ========== FITUR 5: AUTO COLLECT ==========
toggleButton("Auto Collect", function() return autoCollect end, function(v)
    autoCollect = v
    spawn(function()
        while autoCollect do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") then
                    local name = obj.Name:lower()
                    if name:match("collect") or name:match("item") or name:match("orb") or name:match("coin") or 
                       name:match("token") or name:match("gem") or name:match("drop") or name:match("reward") then
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
            wait(0.3)
        end
    end)
end)

-- ========== FITUR 6: AUTO UPGRADE ==========
toggleButton("Auto Upgrade", function() return autoUpgrade end, function(v)
    autoUpgrade = v
    spawn(function()
        while autoUpgrade do
            -- Cari tombol Upgrade
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("upgrade") or txt:match("buy") or txt:match("purchase") or txt:match("level") then
                        btn:Click()
                        wait(0.05)
                    end
                end
            end
            wait(0.2)
        end
    end)
end)

-- ========== FITUR 7: AUTO PET ==========
toggleButton("Auto Pet", function() return autoPet end, function(v)
    autoPet = v
    spawn(function()
        while autoPet do
            -- Cari tombol Pet
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("pet") or txt:match("egg") or txt:match("hatch") or txt:match("gacha") then
                        btn:Click()
                        wait(0.1)
                    end
                end
            end
            -- Cari ClickDetector pet
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("pet") or name:match("egg") or name:match("hatch") then
                            if obj:IsA("ClickDetector") then
                                obj:Click()
                            elseif obj:IsA("ProximityPrompt") then
                                obj:InputHoldStart()
                                wait(0.1)
                                obj:InputHoldEnd()
                            end
                            wait(0.1)
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 22)
credit.Position = UDim2.new(0, 0, 0, 520)
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
print("     VORTEX DIGITAL - SUPER AUTO")
print("     Auto Clicker | +1 Muscle | x2 Power")
print("     Auto Rebirth | Auto Collect")
print("     Auto Upgrade | Auto Pet")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
