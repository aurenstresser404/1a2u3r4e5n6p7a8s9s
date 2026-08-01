-- ============================================
-- VORTEX DIGITAL - AUTO MONEY (PASTI NAMBAH)
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 250, 0, 120)
frame.Position = UDim2.new(0.5, -125, 0.5, -60)
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

-- ========== TOMBOL AUTO MONEY ==========
local autoMoney = false
local moneyBtn = Instance.new("TextButton")
moneyBtn.Size = UDim2.new(0.8, 0, 0, 40)
moneyBtn.Position = UDim2.new(0.1, 0, 0.4, 0)
moneyBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
moneyBtn.BackgroundTransparency = 0.2
moneyBtn.Text = "Auto Money [OFF]"
moneyBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
moneyBtn.TextScaled = true
moneyBtn.Font = Enum.Font.GothamBold
moneyBtn.BorderSizePixel = 1
moneyBtn.BorderColor3 = Color3.fromRGB(0, 100, 200)
moneyBtn.Parent = frame

moneyBtn.MouseButton1Click:Connect(function()
    autoMoney = not autoMoney
    moneyBtn.Text = autoMoney and "Auto Money [ON]" or "Auto Money [OFF]"
    moneyBtn.BackgroundColor3 = autoMoney and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
    print("[VORTEX] Auto Money: " .. (autoMoney and "ON" or "OFF"))
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 18)
credit.Position = UDim2.new(0, 0, 0.8, 0)
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

-- ========== LOOP AUTO MONEY ==========
spawn(function()
    while true do
        if autoMoney then
            -- ========== CARI SEMUA NILAI UANG ==========
            local function addMoney()
                -- Cari di leaderstats
                local leaderstats = player:FindFirstChild("leaderstats")
                if leaderstats then
                    for _, stat in ipairs(leaderstats:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            local name = stat.Name:lower()
                            if name:match("coin") or name:match("money") or name:match("cash") or name:match("point") or 
                               name:match("token") or name:match("gem") or name:match("diamond") or name:match("gold") or
                               name:match("cc") or name:match("bb") or name:match("km") or name:match("m") or
                               name:match("value") or name:match("score") or name:match("currency") then
                                if stat.Value < 999999999 then
                                    stat.Value = stat.Value + 100
                                    print("[VORTEX] " .. stat.Name .. " +100 = " .. stat.Value)
                                end
                            end
                        end
                    end
                end

                -- Cari di semua folder player
                for _, folder in ipairs(player:GetChildren()) do
                    if folder:IsA("Folder") then
                        for _, stat in ipairs(folder:GetChildren()) do
                            if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                                local name = stat.Name:lower()
                                if name:match("coin") or name:match("money") or name:match("cash") or name:match("point") or 
                                   name:match("token") or name:match("gem") or name:match("diamond") or name:match("gold") or
                                   name:match("cc") or name:match("bb") or name:match("km") or name:match("m") or
                                   name:match("value") or name:match("score") or name:match("currency") then
                                    if stat.Value < 999999999 then
                                        stat.Value = stat.Value + 100
                                    end
                                end
                            end
                        end
                    end
                end
            end

            addMoney()
        end
        wait(0.1) -- Tambah uang setiap 0.1 detik (cepat)
    end
end)

print("=========================================")
print("     VORTEX DIGITAL - AUTO MONEY")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Klik tombol 'Auto Money'")
print("2. Uang akan nambah sendiri +100 setiap 0.1 detik")
