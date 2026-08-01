-- ============================================
-- VORTEX DIGITAL - FULL FIX + AUTO UNLOCK WORLDS
-- Speed Walk + Climb | Auto Coin | Auto Piala | Auto Buy Pet | Auto Unlock Worlds
-- SEMUA FITUR BISA ON/OFF
-- VERSION 7.1 - TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE (SEMUA BISA ON/OFF) ==========
local speedEnabled = false
local speedValue = 50
local coinEnabled = false
local pialaEnabled = false
local petEnabled = false
local unlockEnabled = false

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 320, 0, 470)
frame.Position = UDim2.new(0.5, -160, 0.5, -235)
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
scroll.CanvasSize = UDim2.new(0, 0, 0, 430)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 8)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI BUAT TOMBOL TOGGLE (ON/OFF) ==========
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

-- ========== FITUR 1: SPEED WALK + CLIMB (ON/OFF) ==========
sliderInput("Speed Walk + Climb", 16, 250, 50, function(v)
    speedValue = v
    if speedEnabled then
        humanoid.WalkSpeed = v
        humanoid.JumpPower = v * 1.5
        humanoid.AutoRotate = true
    end
    print("[VORTEX] Speed set to: " .. v)
end)

local speedBtn = toggleButton("Speed Walk + Climb", function() return speedEnabled end, function(v)
    speedEnabled = v
    if v then
        humanoid.WalkSpeed = speedValue
        humanoid.JumpPower = speedValue * 1.5
        humanoid.AutoRotate = true
        spawn(function()
            while speedEnabled do
                if humanoid then
                    humanoid.WalkSpeed = speedValue
                    humanoid.JumpPower = speedValue * 1.5
                end
                task.wait(0.1)
            end
        end)
    else
        humanoid.WalkSpeed = 16
        humanoid.JumpPower = 50
    end
end)

-- ========== FITUR 2: AUTO COIN (ON/OFF) ==========
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
            task.wait(0.3)
        end
    end)
end)

-- ========== FITUR 3: AUTO PIALA (ON/OFF) ==========
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
                            task.wait(0.05)
                            
                            local click = obj:FindFirstChild("ClickDetector") or target:FindFirstChild("ClickDetector")
                            if click and click:IsA("ClickDetector") then
                                click:Click()
                            end
                            
                            local prompt = obj:FindFirstChild("ProximityPrompt") or target:FindFirstChild("ProximityPrompt")
                            if prompt and prompt:IsA("ProximityPrompt") then
                                prompt:InputHoldStart()
                                task.wait(0.1)
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
            task.wait(0.5)
        end
    end)
end)

-- ========== FITUR 4: AUTO BUY PET (ON/OFF) ==========
local petBtn = toggleButton("Auto Buy Pet", function() return petEnabled end, function(v)
    petEnabled = v
    spawn(function()
        while petEnabled do
            local bought = false
            
            -- 1. Cari ClickDetector / ProximityPrompt di workspace
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
                                    task.wait(0.1)
                                    obj:InputHoldEnd()
                                    bought = true
                                    print("[VORTEX] Pet purchased via prompt: " .. parent.Name)
                                end
                                task.wait(0.3)
                            end
                        end
                    end
                end
            end
            
            -- 2. Cari GUI Button
            for _, guiObj in ipairs(player.PlayerGui:GetDescendants()) do
                if guiObj:IsA("TextButton") or guiObj:IsA("ImageButton") then
                    local txt = guiObj.Text:lower()
                    if txt:match("buy") or txt:match("purchase") or txt:match("get") or txt:match("claim") then
                        if txt:match("pet") or txt:match("egg") or txt:match("gacha") or txt:match("crate") or txt:match("legend") or txt:match("mythic") or txt:match("god") then
                            guiObj:Click()
                            bought = true
                            print("[VORTEX] Pet bought from GUI: " .. guiObj.Name)
                            task.wait(0.3)
                        end
                    end
                end
            end
            
            -- 3. Cari RemoteEvent
            if not bought then
                for _, container in ipairs({game:GetService("ReplicatedStorage"), game:GetService("ServerScriptService")}) do
                    for _, obj in ipairs(container:GetDescendants()) do
                        if obj:IsA("RemoteEvent") and obj.Name:lower():match("buy") and obj.Name:lower():match("pet") then
                            obj:FireServer()
                            bought = true
                            print("[VORTEX] Pet purchased via RemoteEvent: " .. obj.Name)
                            task.wait(0.3)
                        end
                    end
                end
            end
            
            task.wait(0.5)
        end
    end)
end)

-- ========== FITUR 5: AUTO UNLOCK WORLDS (ON/OFF) ==========
local unlockBtn = toggleButton("Auto Unlock Worlds", function() return unlockEnabled end, function(v)
    unlockEnabled = v
    spawn(function()
        while unlockEnabled do
            local unlocked = false
            
            -- 1. Cari tombol unlock di GUI
            for _, guiObj in ipairs(player.PlayerGui:GetDescendants()) do
                if guiObj:IsA("TextButton") or guiObj:IsA("ImageButton") then
                    local txt = guiObj.Text:lower()
                    if txt:match("unlock") or txt:match("buy") or txt:match("open") or txt:match("claim") or txt:match("next") then
                        if txt:match("world") or txt:match("level") or txt:match("stage") or txt:match("area") or txt:match("map") or txt:match("zone") then
                            guiObj:Click()
                            unlocked = true
                            print("[VORTEX] Unlocked via GUI: " .. guiObj.Name)
                            task.wait(0.2)
                        end
                    end
                end
            end
            
            -- 2. Cari ClickDetector / ProximityPrompt di workspace
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local parent = obj.Parent
                    if parent then
                        local pname = parent.Name:lower()
                        if pname:match("unlock") or pname:match("world") or pname:match("level") or pname:match("stage") or pname:match("area") or pname:match("gate") or pname:match("portal") then
                            if obj:IsA("ClickDetector") then
                                obj:Click()
                                unlocked = true
                                print("[VORTEX] Unlocked via ClickDetector: " .. parent.Name)
                            elseif obj:IsA("ProximityPrompt") then
                                obj:InputHoldStart()
                                task.wait(0.1)
                                obj:InputHoldEnd()
                                unlocked = true
                                print("[VORTEX] Unlocked via ProximityPrompt: " .. parent.Name)
                            end
                            task.wait(0.3)
                        end
                    end
                end
            end
            
            -- 3. Cari RemoteEvent untuk unlock
            for _, container in ipairs({game:GetService("ReplicatedStorage"), game:GetService("ServerScriptService")}) do
                for _, obj in ipairs(container:GetDescendants()) do
                    if obj:IsA("RemoteEvent") then
                        local name = obj.Name:lower()
                        if name:match("unlock") or name:match("world") or name:match("level") or name:match("stage") or name:match("area") or name:match("next") then
                            obj:FireServer()
                            unlocked = true
                            print("[VORTEX] Unlocked via RemoteEvent: " .. obj.Name)
                            task.wait(0.3)
                        end
                    end
                end
            end
            
            -- 4. Ubah nilai di leaderstats
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        local name = stat.Name:lower()
                        if name:match("level") or name:match("stage") or name:match("world") or name:match("area") or name:match("zone") or name:match("rank") then
                            if stat.Value < 9999 then
                                stat.Value = stat.Value + 100
                                unlocked = true
                                print("[VORTEX] " .. stat.Name .. " increased to: " .. stat.Value)
                            end
                        end
                    end
                end
            end
            
            -- 5. Teleport ke portal/gate
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("BasePart") then
                    local name = obj.Name:lower()
                    if name:match("portal") or name:match("gate") or name:match("door") or name:match("teleport") then
                        if root then
                            root.CFrame = obj.CFrame + Vector3.new(0, 2, 0)
                            unlocked = true
                            print("[VORTEX] Teleported to: " .. obj.Name)
                            task.wait(0.2)
                        end
                    end
                end
            end
            
            if not unlocked then
                print("[VORTEX] No unlockable worlds found, retrying...")
            end
            
            task.wait(0.5)
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 30)
credit.Position = UDim2.new(0, 0, 0, 435)
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
print("     VORTEX DIGITAL - FULL FIX")
print("     Speed Walk + Climb | Auto Coin")
print("     Auto Piala | Auto Buy Pet")
print("     Auto Unlock Worlds")
print("     SEMUA FITUR BISA ON/OFF")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
