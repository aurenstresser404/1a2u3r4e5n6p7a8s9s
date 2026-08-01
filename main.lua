-- ============================================
-- VORTEX DIGITAL - SPEED WALK SUPPORT SEMUA
-- Speed Walk (Semua Kondisi) | Auto Coin | Auto Piala | Auto Buy Pet
-- VERSION 6.0 - 100% WORKING
-- TELEGRAM : @realvortexdigital
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
frame.Size = UDim2.new(0, 320, 0, 420)
frame.Position = UDim2.new(0.5, -160, 0.5, -210)
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
scroll.CanvasSize = UDim2.new(0, 0, 0, 380)
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

-- ========== FITUR 1: SPEED WALK (SUPPORT SEMUA KONDISI) ==========
sliderInput("Speed Walk", 16, 250, 50, function(v)
    speedValue = v
    if speedEnabled and humanoid then
        humanoid.WalkSpeed = v
        humanoid.JumpPower = v * 1.2
    end
    print("[VORTEX] Speed set to: " .. v)
end)

local speedBtn = toggleButton("Speed Walk", function() return speedEnabled end, function(v)
    speedEnabled = v
    if v then
        humanoid.WalkSpeed = speedValue
        humanoid.JumpPower = speedValue * 1.2
        -- Loop untuk menjaga speed tetap apapun kondisi
        spawn(function()
            while speedEnabled do
                if humanoid then
                    -- Set speed untuk semua kondisi
                    humanoid.WalkSpeed = speedValue
                    humanoid.JumpPower = speedValue * 1.2
                    
                    -- Untuk climbing (jika ada sistem climb)
                    local climbModule = character:FindFirstChild("ClimbModule")
                    if climbModule then
                        climbModule.Speed = speedValue
                    end
                    
                    -- Untuk flying (jika ada)
                    local flyModule = character:FindFirstChild("FlyModule")
                    if flyModule then
                        flyModule.Speed = speedValue
                    end
                    
                    -- Untuk swimming
                    humanoid.SwimSpeed = speedValue * 0.8
                end
                wait(0.05) -- update cepat agar tetap stabil
            end
        end)
    else
        humanoid.WalkSpeed = 16
        humanoid.JumpPower = 50
        humanoid.SwimSpeed = 10
    end
end)

-- ========== FITUR 2: AUTO COIN ==========
local coinBtn = toggleButton("Auto Coin", function() return coinEnabled end, function(v)
    coinEnabled = v
    spawn(function()
        while coinEnabled do
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        local name = stat.Name:lower()
                        if name:match("coin") or name:match("money") or name:match("cash") or name:match("point") or name:match("token") or name:match("gems") or name:match("diamond") then
                            if stat.Value > 0 and stat.Value < 999999999 then
                                stat.Value = stat.Value * 2
                                print("[VORTEX] " .. stat.Name .. " doubled: " .. stat.Value)
                            end
                        end
                    end
                end
            end
            for _, folder in ipairs(player:GetChildren()) do
                if folder:IsA("Folder") then
                    for _, stat in ipairs(folder:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            local name = stat.Name:lower()
                            if name:match("coin") or name:match("money") or name:match("cash") or name:match("point") or name:match("token") or name:match("gems") or name:match("diamond") then
                                if stat.Value > 0 and stat.Value < 999999999 then
                                    stat.Value = stat.Value * 2
                                    print("[VORTEX] " .. stat.Name .. " doubled: " .. stat.Value)
                                end
                            end
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 3: AUTO PIALA ==========
local pialaBtn = toggleButton("Auto Piala", function() return pialaEnabled end, function(v)
    pialaEnabled = v
    spawn(function()
        local collectedCache = {}
        while pialaEnabled do
            local collected = 0
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") or obj:IsA("Tool") or obj:IsA("BasePart") then
                    local name = obj.Name:lower()
                    if name:match("trophy") or name:match("piala") or name:match("cup") or name:match("medal") or name:match("achievement") or name:match("reward") or name:match("chest") or name:match("crystal") then
                        if collectedCache[obj] then
                            if obj:IsA("Part") and obj.Parent then
                            else
                                collectedCache[obj] = nil
                            end
                            goto continue
                        end
                        
                        local target = nil
                        if obj:IsA("Part") or obj:IsA("BasePart") then
                            target = obj
                        elseif obj:IsA("Model") then
                            target = obj:FindFirstChild("HumanoidRootPart") or obj:FindFirstChild("Head") or obj:FindFirstChild("Part") or obj.PrimaryPart
                        elseif obj:IsA("Tool") then
                            target = obj:FindFirstChild("Handle")
                        end
                        
                        if target and root then
                            root.CFrame = target.CFrame + Vector3.new(0, 2, 0)
                            wait(0.05)
                            
                            local click = obj:FindFirstChild("ClickDetector") or target:FindFirstChild("ClickDetector")
                            if click and click:IsA("ClickDetector") then
                                click:Click()
                            end
                            
                            local prompt = obj:FindFirstChild("ProximityPrompt") or target:FindFirstChild("ProximityPrompt")
                            if prompt and prompt:IsA("ProximityPrompt") then
                                prompt:InputHoldStart()
                                wait(0.1)
                                prompt:InputHoldEnd()
                            end
                            
                            collectedCache[obj] = true
                            collected = collected + 1
                            print("[VORTEX] Piala collected: " .. obj.Name)
                        end
                    end
                end
                ::continue::
            end
            if collected > 0 then
                print("[VORTEX] Total piala collected this cycle: " .. collected)
            end
            wait(0.5)
        end
    end)
end)

-- ========== FITUR 4: AUTO BUY PET ==========
local petBtn = toggleButton("Auto Buy Pet", function() return petEnabled end, function(v)
    petEnabled = v
    spawn(function()
        while petEnabled do
            local bought = false
            
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local parent = obj.Parent
                    if parent then
                        local pname = parent.Name:lower()
                        if pname:match("pet") or pname:match("shop") or pname:match("egg") or pname:match("box") or pname:match("gacha") or pname:match("crate") or pname:match("purchase") then
                            if pname:match("legend") or pname:match("mythic") or pname:match("god") or pname:match("ultra") or pname:match("epic") or pname:match("rare") then
                                if obj:IsA("ClickDetector") then
                                    obj:Click()
                                    bought = true
                                    print("[VORTEX] Pet purchased: " .. parent.Name)
                                elseif obj:IsA("ProximityPrompt") then
                                    obj:InputHoldStart()
                                    wait(0.1)
                                    obj:InputHoldEnd()
                                    bought = true
                                    print("[VORTEX] Pet purchased via prompt: " .. parent.Name)
                                end
                                wait(0.3)
                            end
                        end
                    end
                end
            end
            
            for _, guiObj in ipairs(player.PlayerGui:GetDescendants()) do
                if guiObj:IsA("TextButton") or guiObj:IsA("ImageButton") then
                    local txt = guiObj.Text:lower()
                    if txt:match("buy") or txt:match("purchase") or txt:match("get") or txt:match("claim") then
                        if txt:match("pet") or txt:match("egg") or txt:match("gacha") or txt:match("crate") or txt:match("legend") or txt:match("mythic") or txt:match("god") then
                            guiObj:Click()
                            bought = true
                            print("[VORTEX] Pet bought from GUI: " .. guiObj.Name)
                            wait(0.3)
                        end
                    end
                end
            end
            
            if not bought then
                for _, container in ipairs({game:GetService("ReplicatedStorage"), game:GetService("ServerScriptService")}) do
                    for _, obj in ipairs(container:GetDescendants()) do
                        if obj:IsA("RemoteEvent") and obj.Name:lower():match("buy") and obj.Name:lower():match("pet") then
                            obj:FireServer()
                            bought = true
                            print("[VORTEX] Pet purchased via RemoteEvent: " .. obj.Name)
                            wait(0.3)
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

-- ========== NOTIFIKASI ==========
print("=========================================")
print("     VORTEX DIGITAL - SPEED SUPPORT ALL")
print("     Speed Walk (Semua Kondisi) | Auto Coin")
print("     Auto Piala | Auto Buy Pet")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
