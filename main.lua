-- ============================================
-- VORTEX DIGITAL - GUI PASTI MUNCUL
-- Speed Walk | Auto Coin | Auto Piala | Auto Buy Pet | Auto Unlock Worlds
-- SEMUA FITUR BISA ON/OFF
-- TELEGRAM : @realvortexdigital
-- ============================================

-- Tunggu player dan karakter benar-benar siap
local player = game.Players.LocalPlayer
if not player then
    game.Players:WaitForChild("LocalPlayer")
    player = game.Players.LocalPlayer
end

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

-- ========== BUAT GUI DENGAN METODE PALING AMAN ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.ResetOnSpawn = false -- Biar ga ilang saat respawn
gui.Parent = player:WaitForChild("PlayerGui")

-- Jika gagal, coba parent ke CoreGui
if not gui.Parent then
    gui.Parent = game:GetService("CoreGui")
end

-- Frame utama
local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 300, 0, 420)
frame.Position = UDim2.new(0.5, -150, 0.5, -210)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 25)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 0
frame.BorderColor3 = Color3.fromRGB(0, 150, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Shadow / efek pinggiran
local border = Instance.new("Frame")
border.Size = UDim2.new(1, 4, 1, 4)
border.Position = UDim2.new(-0.01, 0, -0.01, 0)
border.BackgroundColor3 = Color3.fromRGB(0, 150, 255)
border.BackgroundTransparency = 0.3
border.BorderSizePixel = 0
border.Parent = frame

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.Position = UDim2.new(0, 0, 0, 0)
title.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -50)
scroll.Position = UDim2.new(0, 5, 0, 42)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 400)
scroll.ScrollBarThickness = 4
scroll.ScrollBarImageColor3 = Color3.fromRGB(0, 150, 255)
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 6)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI BUAT TOMBOL ==========
local function makeToggle(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, -10, 0, 38)
    btn.BackgroundColor3 = Color3.fromRGB(30, 30, 60)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.GothamBold
    btn.BorderSizePixel = 1
    btn.BorderColor3 = Color3.fromRGB(0, 100, 200)
    btn.Parent = scroll
    
    btn.MouseButton1Click:Connect(function()
        local new = not getter()
        setter(new)
        btn.Text = text .. (new and " [ON]" or " [OFF]")
        btn.BackgroundColor3 = new and Color3.fromRGB(0, 120, 0) or Color3.fromRGB(30, 30, 60)
        print("[VORTEX] " .. text .. ": " .. (new and "ON" or "OFF"))
    end)
    return btn
end

-- ========== FUNGSI SLIDER ==========
local function makeSlider(label, minv, maxv, defaultv, callback)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(1, -10, 0, 38)
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
    box.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    box.Text = tostring(defaultv)
    box.TextColor3 = Color3.fromRGB(255, 255, 255)
    box.TextScaled = true
    box.Font = Enum.Font.Gotham
    box.BorderSizePixel = 1
    box.BorderColor3 = Color3.fromRGB(0, 100, 200)
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

-- ========== BUAT FITUR ==========

-- 1. Speed Walk
makeSlider("Speed Walk", 16, 250, 50, function(v)
    speedVal = v
    if speedOn and humanoid then humanoid.WalkSpeed = v end
end)
makeToggle("Speed Walk", function() return speedOn end, function(v)
    speedOn = v
    if v then
        humanoid.WalkSpeed = speedVal
        humanoid.JumpPower = speedVal * 1.2
    else
        humanoid.WalkSpeed = 16
        humanoid.JumpPower = 50
    end
end)

-- 2. Auto Coin
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

-- 3. Auto Piala
makeToggle("Auto Piala", function() return pialaOn end, function(v)
    pialaOn = v
    spawn(function()
        while pialaOn do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") then
                    local n = obj.Name:lower()
                    if n:match("trophy") or n:match("piala") or n:match("cup") or n:match("medal") or n:match("chest") then
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

-- 4. Auto Buy Pet
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

-- 5. Auto Unlock Worlds
makeToggle("Auto Unlock Worlds", function() return unlockOn end, function(v)
    unlockOn = v
    spawn(function()
        while unlockOn do
            -- Cari tombol GUI
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
            -- Naikkan leaderstats
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
credit.Size = UDim2.new(1, -10, 0, 25)
credit.Position = UDim2.new(0, 5, 0, 380)
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

-- ========== NOTIFIKASI ==========
print("=========================================")
print("     VORTEX DIGITAL - GUI PASTI MUNCUL")
print("     Speed Walk | Auto Coin | Auto Piala")
print("     Auto Buy Pet | Auto Unlock Worlds")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")

-- Notifikasi di layar
pcall(function()
    game:GetService("StarterGui"):SetCore("SendNotification", {
        Title = "VORTEX DIGITAL",
        Text = "GUI Loaded! TELEGRAM : @realvortexdigital",
        Duration = 3
    })
end)
