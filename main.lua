-- ============================================
-- VORTEX DIGITAL - AUTO COIN (PASTI WORK)
-- Menambah SEMUA nilai angka secara REAL
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer

-- ========== VARIABEL ==========
local autoCoin = false
local addAmount = 1000

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 280, 0, 170)
frame.Position = UDim2.new(0.5, -140, 0.5, -85)
frame.BackgroundColor3 = Color3.fromRGB(15, 15, 25)
frame.BackgroundTransparency = 0.1
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 35)
title.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX DIGITAL"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- ========== SLIDER JUMLAH ==========
local amountFrame = Instance.new("Frame")
amountFrame.Size = UDim2.new(0.9, 0, 0, 35)
amountFrame.Position = UDim2.new(0.05, 0, 0.25, 0)
amountFrame.BackgroundTransparency = 1
amountFrame.Parent = frame

local amountLabel = Instance.new("TextLabel")
amountLabel.Size = UDim2.new(0.5, 0, 1, 0)
amountLabel.Text = "Jumlah Tambah:"
amountLabel.TextColor3 = Color3.fromRGB(200, 200, 200)
amountLabel.TextScaled = true
amountLabel.Font = Enum.Font.Gotham
amountLabel.BackgroundTransparency = 1
amountLabel.Parent = amountFrame

local amountBox = Instance.new("TextBox")
amountBox.Size = UDim2.new(0.35, 0, 0.8, 0)
amountBox.Position = UDim2.new(0.6, 0, 0.1, 0)
amountBox.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
amountBox.Text = tostring(addAmount)
amountBox.TextColor3 = Color3.fromRGB(255, 255, 255)
amountBox.TextScaled = true
amountBox.Font = Enum.Font.Gotham
amountBox.BorderSizePixel = 0
amountBox.Parent = amountFrame

amountBox.FocusLost:Connect(function()
    local n = tonumber(amountBox.Text)
    if n and n > 0 then
        addAmount = math.floor(n)
        amountBox.Text = tostring(addAmount)
        print("[VORTEX] Jumlah: " .. addAmount)
    else
        amountBox.Text = tostring(addAmount)
    end
end)

-- ========== TOMBOL AUTO COIN ==========
local coinBtn = Instance.new("TextButton")
coinBtn.Size = UDim2.new(0.8, 0, 0, 38)
coinBtn.Position = UDim2.new(0.1, 0, 0.55, 0)
coinBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
coinBtn.BackgroundTransparency = 0.2
coinBtn.Text = "Auto Coin [OFF]"
coinBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
coinBtn.TextScaled = true
coinBtn.Font = Enum.Font.GothamBold
coinBtn.BorderSizePixel = 1
coinBtn.BorderColor3 = Color3.fromRGB(0, 100, 200)
coinBtn.Parent = frame

coinBtn.MouseButton1Click:Connect(function()
    autoCoin = not autoCoin
    coinBtn.Text = autoCoin and "Auto Coin [ON]" or "Auto Coin [OFF]"
    coinBtn.BackgroundColor3 = autoCoin and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
    print("[VORTEX] Auto Coin: " .. (autoCoin and "ON" or "OFF"))
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 18)
credit.Position = UDim2.new(0, 0, 0.82, 0)
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

-- ========== LOOP AUTO COIN (PASTI WORK) ==========
spawn(function()
    while true do
        if autoCoin then
            -- ===== CARI SEMUA NILAI ANGKA =====
            local function addToAllValues()
                -- 1. Cari di leaderstats
                local leaderstats = player:FindFirstChild("leaderstats")
                if leaderstats then
                    for _, stat in ipairs(leaderstats:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            if stat.Value < 999999999 then
                                stat.Value = stat.Value + addAmount
                                print("[VORTEX] " .. stat.Name .. " +" .. addAmount .. " = " .. stat.Value)
                            end
                        end
                    end
                end

                -- 2. Cari di semua folder player
                for _, folder in ipairs(player:GetChildren()) do
                    if folder:IsA("Folder") then
                        for _, stat in ipairs(folder:GetChildren()) do
                            if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                                if stat.Value < 999999999 then
                                    stat.Value = stat.Value + addAmount
                                end
                            end
                        end
                    end
                end

                -- 3. Cari di Backpack
                local backpack = player:FindFirstChild("Backpack")
                if backpack then
                    for _, item in ipairs(backpack:GetChildren()) do
                        if item:IsA("Tool") then
                            for _, attr in ipairs(item:GetChildren()) do
                                if attr:IsA("IntValue") or attr:IsA("NumberValue") then
                                    if attr.Value < 999999999 then
                                        attr.Value = attr.Value + addAmount
                                    end
                                end
                            end
                        end
                    end
                end

                -- 4. Cari di semua tool di character
                local character = player.Character
                if character then
                    for _, tool in ipairs(character:GetChildren()) do
                        if tool:IsA("Tool") then
                            for _, attr in ipairs(tool:GetChildren()) do
                                if attr:IsA("IntValue") or attr:IsA("NumberValue") then
                                    if attr.Value < 999999999 then
                                        attr.Value = attr.Value + addAmount
                                    end
                                end
                            end
                        end
                    end
                end
            end

            addToAllValues()
        end
        wait(0.1)
    end
end)

print("=========================================")
print("     VORTEX DIGITAL - AUTO COIN")
print("     Menambah SEMUA nilai angka!")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
