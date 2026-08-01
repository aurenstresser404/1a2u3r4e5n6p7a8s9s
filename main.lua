-- ============================================
-- VORTEX DIGITAL - AUTO BOOST TERKENDALI (PASTI WORK)
-- Speed Walk | Auto Coin | Auto Piala | Auto Buy Pet | Auto Boost (Work)
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
local autoBoostEnabled = false

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 320, 0, 480)
frame.Position = UDim2.new(0.5, -160, 0.5, -240)
frame.BackgroundColor3 = Color3.fromRGB(15, 15, 25)
frame.BackgroundTransparency = 0.1
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 150, 255)
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
scroll.Size = UDim2.new(1, -10, 1, -50)
scroll.Position = UDim2.new(0, 5, 0, 45)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 450)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 6)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI TOMBOL ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, -10, 0, 38)
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

-- ========== FUNGSI SLIDER ==========
local function sliderInput(label, minv, maxv, defaultv, callback)
    local f = Instance.new("Frame")
    f.Size = UDim2.new(1, -10, 0, 40)
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
        humanoid.JumpPower = v * 1.2
    end
end)

toggleButton("Speed Walk", function() return speedEnabled end, function(v)
    speedEnabled = v
    if v then
        humanoid.WalkSpeed = speedValue
        humanoid.JumpPower = speedValue * 1.2
        humanoid.SwimSpeed = speedValue * 0.8
        spawn(function()
            while speedEnabled do
                if humanoid then
                    humanoid.WalkSpeed = speedValue
                    humanoid.JumpPower = speedValue * 1.2
                    humanoid.SwimSpeed = speedValue * 0.8
                end
                wait(0.05)
            end
        end)
    else
        humanoid.WalkSpeed = 16
        humanoid.JumpPower = 50
        humanoid.SwimSpeed = 10
    end
end)

-- ========== FITUR 2: AUTO COIN ==========
toggleButton("Auto Coin", function() return coinEnabled end, function(v)
    coinEnabled = v
    spawn(function()
        while coinEnabled do
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        if stat.Value > 0 and stat.Value < 999999999 then
                            stat.Value = stat.Value * 2
                            print("[VORTEX] Coin doubled: " .. stat.Value)
                        end
                    end
                end
            end
            wait(0.3)
        end
    end)
end)

-- ========== FITUR 3: AUTO PIALA ==========
toggleButton("Auto Piala", function() return pialaEnabled end, function(v)
    pialaEnabled = v
    spawn(function()
        while pialaEnabled do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") or obj:IsA("Model") then
                    local name = obj.Name:lower()
                    if name:match("trophy") or name:match("piala") or name:match("cup") or name:match("medal") or name:match("chest") then
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
toggleButton("Auto Buy Pet", function() return petEnabled end, function(v)
    petEnabled = v
    spawn(function()
        while petEnabled do
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

-- ========== FITUR 5: AUTO BOOST TERKENDALI (PASTI WORK) ==========
toggleButton("Auto Boost (Terkendali)", function() return autoBoostEnabled end, function(v)
    autoBoostEnabled = v
    spawn(function()
        while autoBoostEnabled do
            -- ========== CARI SEMUA NILAI ANGKA ==========
            local function boostAllValues()
                -- Cari di leaderstats
                local leaderstats = player:FindFirstChild("leaderstats")
                if leaderstats then
                    for _, stat in ipairs(leaderstats:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            if stat.Value < 999999999 then
                                -- Naikkan semua nilai +50 per loop (stabil)
                                stat.Value = stat.Value + 50
                                print("[VORTEX] " .. stat.Name .. " +50 = " .. stat.Value)
                            end
                        end
                    end
                end

                -- Cari di semua folder player
                for _, folder in ipairs(player:GetChildren()) do
                    if folder:IsA("Folder") then
                        for _, stat in ipairs(folder:GetChildren()) do
                            if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                                if stat.Value < 999999999 then
                                    stat.Value = stat.Value + 50
                                    print("[VORTEX] " .. stat.Name .. " +50 = " .. stat.Value)
                                end
                            end
                        end
                    end
                end

                -- Cari di Inventory / Backpack
                local backpack = player:FindFirstChild("Backpack")
                if backpack then
                    for _, item in ipairs(backpack:GetChildren()) do
                        if item:IsA("Tool") then
                            for _, attr in ipairs(item:GetChildren()) do
                                if attr:IsA("IntValue") or attr:IsA("NumberValue") then
                                    if attr.Value < 999999999 then
                                        attr.Value = attr.Value + 50
                                    end
                                end
                            end
                        end
                    end
                end
            end

            -- Jalankan boost
            boostAllValues()

            -- ========== AUTO CLIMB (STABIL) ==========
            local function autoClimb()
                if root then
                    local raycastParams = RaycastParams.new()
                    raycastParams.FilterDescendantsInstances = {character}
                    raycastParams.FilterType = Enum.RaycastFilterType.Blacklist
                    local direction = root.CFrame.LookVector * 5
                    local rayResult = workspace:Raycast(root.Position, direction, raycastParams)
                    
                    if rayResult then
                        local normal = rayResult.Normal
                        root.Velocity = Vector3.new(0, 15, 0) + normal * 5
                    else
                        if humanoid then
                            humanoid.Jump = true
                        end
                    end
                end
            end
            autoClimb()

            -- ========== AUTO KLIK TOMBOL BOOST ==========
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") then
                    local txt = btn.Text:lower()
                    if txt:match("2xspeed") or txt:match("boost") or txt:match("speed") then
                        btn:Click()
                        wait(0.1)
                    end
                end
            end

            -- ========== AUTO COLLECT ITEM ==========
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") then
                    local name = obj.Name:lower()
                    if name:match("collect") or name:match("item") or name:match("orb") or name:match("coin") or name:match("token") or name:match("gem") then
                        if root then
                            root.CFrame = obj.CFrame + Vector3.new(0, 2, 0)
                            wait(0.05)
                            local click = obj:FindFirstChild("ClickDetector")
                            if click then click:Click() end
                        end
                    end
                end
            end

            wait(0.5) -- Loop stabil
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, -10, 0, 25)
credit.Position = UDim2.new(0, 5, 0, 445)
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
print("     VORTEX DIGITAL - AUTO BOOST WORK")
print("     Speed Walk | Auto Coin | Auto Piala")
print("     Auto Buy Pet | Auto Boost (Terkendali)")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Aktifkan 'Auto Boost (Terkendali)'")
print("2. Semua nilai angka akan naik +50 per detik")
print("3. Stabil dan aman!")
