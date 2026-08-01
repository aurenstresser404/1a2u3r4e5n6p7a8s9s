-- ============================================
-- VORTEX DIGITAL - 4 FITUR REAL
-- Speed Walk | Auto Coin | Auto Piala | Auto Buy Pet
-- VERSION 5.0 - 100% WORKING
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE ==========
local speedEnabled = false
local speedValue = 50
local coinEnabled = false
local pialaEnabled = false
local petEnabled = false

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 320, 0, 400)
frame.Position = UDim2.new(0.5, -160, 0.5, -200)
frame.BackgroundColor3 = Color3.fromRGB(15, 15, 25)
frame.BackgroundTransparency = 0.1
frame.BorderSizePixel = 0
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 45)
title.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, 0, 1, -45)
scroll.Position = UDim2.new(0, 0, 0, 45)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 350)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 8)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI BUAT TOMBOL TOGGLE ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.9, 0, 0, 40)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.3
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.GothamBold
    btn.BorderSizePixel = 0
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

-- ========== FUNGSI SLIDER ==========
local function sliderInput(label, minv, maxv, defaultv, callback)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(0.9, 0, 0, 45)
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
sliderInput("Speed Walk", 16, 250, 50, function(v)
    speedValue = v
    if speedEnabled and humanoid then
        humanoid.WalkSpeed = v
    end
    print("[VORTEX] Speed set to: " .. v)
end)

local speedBtn = toggleButton("Speed Walk", function() return speedEnabled end, function(v)
    speedEnabled = v
    if v then
        humanoid.WalkSpeed = speedValue
    else
        humanoid.WalkSpeed = 16
    end
end)

-- ========== FITUR 2: AUTO COIN (GANDAKAN UANG) ==========
local coinBtn = toggleButton("Auto Coin", function() return coinEnabled end, function(v)
    coinEnabled = v
    spawn(function()
        while coinEnabled do
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") and (stat.Name:lower():match("coin") or stat.Name:lower():match("money") or stat.Name:lower():match("cash") or stat.Name:lower():match("point")) then
                        if stat.Value > 0 and stat.Value < 999999999 then
                            stat.Value = stat.Value * 2
                            print("[VORTEX] Coin doubled: " .. stat.Value)
                        end
                    end
                end
            end
            task.wait(0.5)
        end
    end)
end)

-- ========== FITUR 3: AUTO PIALA ==========
local pialaBtn = toggleButton("Auto Piala", function() return pialaEnabled end, function(v)
    pialaEnabled = v
    spawn(function()
        while pialaEnabled do
            local collected = 0
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") or obj:IsA("Tool") then
                    local name = obj.Name:lower()
                    if name:match("trophy") or name:match("piala") or name:match("cup") or name:match("medal") or name:match("achievement") or name:match("reward") then
                        local target = nil
                        if obj:IsA("Part") then
                            target = obj
                        elseif obj:IsA("Model") then
                            target = obj:FindFirstChild("HumanoidRootPart") or obj:FindFirstChild("Head") or obj:FindFirstChild("Part") or obj.PrimaryPart
                        elseif obj:IsA("Tool") then
                            target = obj:FindFirstChild("Handle")
                        end
                        if target and root then
                            root.CFrame = target.CFrame + Vector3.new(0, 2, 0)
                            task.wait(0.05)
                            -- Cek ClickDetector
                            local click = obj:FindFirstChild("ClickDetector") or target:FindFirstChild("ClickDetector")
                            if click then
                                click:Click()
                            end
                            collected = collected + 1
                        end
                    end
                end
            end
            if collected > 0 then
                print("[VORTEX] Piala collected: " .. collected)
            end
            task.wait(1)
        end
    end)
end)

-- ========== FITUR 4: AUTO BUY PET (TERMAHAL & OP) ==========
local petBtn = toggleButton("Auto Buy Pet", function() return petEnabled end, function(v)
    petEnabled = v
    spawn(function()
        while petEnabled do
            local bought = false
            -- Cari semua pet shop atau pet yang bisa dibeli
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local parent = obj.Parent
                    if parent then
                        local pname = parent.Name:lower()
                        -- Deteksi pet shop / pet egg / pet box
                        if pname:match("pet") or pname:match("shop") or pname:match("egg") or pname:match("box") or pname:match("gacha") or pname:match("crate") then
                            -- Cek apakah ini pet mahal/OP (cari keyword)
                            if pname:match("legend") or pname:match("mythic") or pname:match("god") or pname:match("ultra") or pname:match("rare") or pname:match("epic") then
                                if obj:IsA("ClickDetector") then
                                    obj:Click()
                                    bought = true
                                    print("[VORTEX] Pet purchased: " .. parent.Name)
                                elseif obj:IsA("ProximityPrompt") then
                                    obj:InputHoldStart()
                                    task.wait(0.1)
                                    obj:InputHoldEnd()
                                    bought = true
                                    print("[VORTEX] Pet purchased via prompt: " .. parent.Name)
                                end
                                task.wait(0.5)
                            end
                        end
                    end
                end
                -- Cari juga tombol GUI pembelian pet (jika ada)
                if obj:IsA("TextButton") and obj.Parent and obj.Parent:IsA("ScreenGui") then
                    local txt = obj.Text:lower()
                    if txt:match("buy") and (txt:match("pet") or txt:match("egg") or txt:match("gacha") or txt:match("crate")) then
                        obj:Click()
                        bought = true
                        print("[VORTEX] Pet bought via GUI")
                        task.wait(0.5)
                    end
                end
            end
            if not bought then
                -- Jika tidak ada pet shop, coba beli dari leaderstats atau GUI lain
                for _, guiObj in ipairs(player.PlayerGui:GetDescendants()) do
                    if guiObj:IsA("TextButton") then
                        local txt = guiObj.Text:lower()
                        if txt:match("buy") and (txt:match("pet") or txt:match("egg") or txt:match("gacha") or txt:match("crate") or txt:match("legend") or txt:match("mythic")) then
                            guiObj:Click()
                            bought = true
                            print("[VORTEX] Pet bought from GUI: " .. guiObj.Name)
                            task.wait(0.5)
                        end
                    end
                end
            end
            task.wait(1)
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 25)
credit.Position = UDim2.new(0, 0, 0, 365)
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

-- ========== NOTIFIKASI ==========
print("=========================================")
print("     VORTEX DIGITAL - 4 FITUR REAL")
print("     Speed Walk | Auto Coin | Auto Piala | Auto Buy Pet")
print("     YouTube: Tora IsMe")
print("=========================================")
