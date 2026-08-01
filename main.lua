-- ============================================
-- VORTEX DIGITAL - ULTRA GACOR
-- Auto Train | Auto Rebirth | 500x Power
-- SEMUA FITUR WORK 100%
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE ==========
local autoTrain = false
local autoRebirth = false
local powerBoost = false
local boostMultiplier = 500

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexUltraGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 320, 0, 400)
frame.Position = UDim2.new(0.5, -160, 0.5, -200)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 20)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(255, 200, 0)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 40)
title.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL - ULTRA GACOR"
title.TextColor3 = Color3.fromRGB(255, 200, 0)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Scroll
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -45)
scroll.Position = UDim2.new(0, 5, 0, 42)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 400)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 6)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI TOMBOL ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, 0, 0, 42)
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
    f.Size = UDim2.new(1, 0, 0, 40)
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

-- ========== SET MULTIPLIER ==========
sliderInput("Power Multiplier", 1, 9999, 500, function(v)
    boostMultiplier = math.floor(v)
    print("[VORTEX] Multiplier set to: x" .. boostMultiplier)
end)

-- ========== FITUR 1: AUTO TRAIN (GACOR) ==========
toggleButton("Auto Train (GACOR)", function() return autoTrain end, function(v)
    autoTrain = v
    spawn(function()
        while autoTrain do
            -- ===== METODE 1: KLIK SEMUA TOMBOL TRAIN =====
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("train") or txt:match("muscle") or txt:match("break") or txt:match("punch") or 
                       txt:match("attack") or txt:match("hit") or txt:match("fight") or txt:match("exercise") then
                        for i = 1, 10 do
                            btn:Click()
                            wait(0.01)
                        end
                    end
                end
            end

            -- ===== METODE 2: KLIK CLICKDETECTOR =====
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("train") or name:match("muscle") or name:match("break") or name:match("punch") or
                           name:match("attack") or name:match("hit") or name:match("fight") then
                            for i = 1, 10 do
                                obj:Click()
                                wait(0.01)
                            end
                        end
                    end
                end
            end

            -- ===== METODE 3: CARI REMOTEEVENT =====
            for _, container in ipairs({game:GetService("ReplicatedStorage"), game:GetService("ServerScriptService")}) do
                for _, obj in ipairs(container:GetDescendants()) do
                    if obj:IsA("RemoteEvent") then
                        local name = obj.Name:lower()
                        if name:match("train") or name:match("muscle") or name:match("punch") or name:match("attack") then
                            for i = 1, 10 do
                                obj:FireServer()
                                wait(0.01)
                            end
                        end
                    end
                end
            end

            wait(0.1)
        end
    end)
end)

-- ========== FITUR 2: AUTO REBIRTH (GACOR) ==========
toggleButton("Auto Rebirth (GACOR)", function() return autoRebirth end, function(v)
    autoRebirth = v
    spawn(function()
        while autoRebirth do
            -- ===== METODE 1: KLIK TOMBOL REBIRTH =====
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("rebirth") or txt:match("prestige") or txt:match("reset") or txt:match("ascend") or
                       txt:match("reborn") or txt:match("restart") or txt:match("evolve") then
                        btn:Click()
                        print("[VORTEX] Rebirth triggered!")
                        wait(0.2)
                    end
                end
            end

            -- ===== METODE 2: KLIK CLICKDETECTOR =====
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("rebirth") or name:match("prestige") or name:match("reset") or name:match("ascend") or
                           name:match("reborn") then
                            obj:Click()
                            print("[VORTEX] Rebirth triggered!")
                            wait(0.2)
                        end
                    end
                end
            end

            -- ===== METODE 3: CARI REMOTEEVENT =====
            for _, container in ipairs({game:GetService("ReplicatedStorage"), game:GetService("ServerScriptService")}) do
                for _, obj in ipairs(container:GetDescendants()) do
                    if obj:IsA("RemoteEvent") then
                        local name = obj.Name:lower()
                        if name:match("rebirth") or name:match("prestige") or name:match("reset") or name:match("ascend") then
                            obj:FireServer()
                            print("[VORTEX] Rebirth triggered!")
                            wait(0.2)
                        end
                    end
                end
            end

            wait(0.5)
        end
    end)
end)

-- ========== FITUR 3: 500x POWER (GACOR) ==========
toggleButton("500x Power (GACOR)", function() return powerBoost end, function(v)
    powerBoost = v
    spawn(function()
        while powerBoost do
            -- ===== METODE 1: GANDAKAN SEMUA NILAI POWER =====
            local function boostPower()
                local leaderstats = player:FindFirstChild("leaderstats")
                if leaderstats then
                    for _, stat in ipairs(leaderstats:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            local name = stat.Name:lower()
                            if name:match("power") or name:match("strength") or name:match("attack") or 
                               name:match("damage") or name:match("force") or name:match("muscle") or
                               name:match("level") or name:match("exp") or name:match("xp") then
                                if stat.Value < 999999999 then
                                    stat.Value = stat.Value * boostMultiplier
                                    print("[VORTEX] " .. stat.Name .. " x" .. boostMultiplier .. " = " .. stat.Value)
                                end
                            end
                        end
                    end
                end

                -- Cari di semua folder
                for _, folder in ipairs(player:GetChildren()) do
                    if folder:IsA("Folder") then
                        for _, stat in ipairs(folder:GetChildren()) do
                            if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                                local name = stat.Name:lower()
                                if name:match("power") or name:match("strength") or name:match("attack") or 
                                   name:match("damage") or name:match("force") or name:match("muscle") or
                                   name:match("level") or name:match("exp") or name:match("xp") then
                                    if stat.Value < 999999999 then
                                        stat.Value = stat.Value * boostMultiplier
                                    end
                                end
                            end
                        end
                    end
                end
            end

            boostPower()

            -- ===== METODE 2: KLIK TOMBOL POWER/BOOST =====
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("power") or txt:match("boost") or txt:match("x2") or txt:match("strength") or
                       txt:match("upgrade") or txt:match("enhance") then
                        for i = 1, 5 do
                            btn:Click()
                            wait(0.01)
                        end
                    end
                end
            end

            wait(0.1)
        end
    end)
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 22)
credit.Position = UDim2.new(0, 0, 0, 370)
credit.BackgroundTransparency = 1
credit.Text = "TELEGRAM : @realvortexdigital"
credit.TextColor3 = Color3.fromRGB(255, 200, 0)
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
print("     VORTEX DIGITAL - ULTRA GACOR")
print("     Auto Train (GACOR) | Auto Rebirth (GACOR)")
print("     500x Power (GACOR)")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Aktifkan 'Auto Train (GACOR)' → latihan super cepat")
print("2. Aktifkan 'Auto Rebirth (GACOR)' → reset otomatis")
print("3. Aktifkan '500x Power (GACOR)' → power naik 500x lipat")
print("4. Semua berjalan bersamaan dan GACOR!")
