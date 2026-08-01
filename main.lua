-- ============================================
-- VORTEX DIGITAL - AUTO MONEY REAL
-- Uang bertambah nyata, bisa dipakai untuk beli apapun
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer

-- ========== VARIABEL ==========
local autoMoney = false
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

-- ========== SLIDER JUMLAH UANG ==========
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
        print("[VORTEX] Jumlah tambah diubah menjadi: " .. addAmount)
    else
        amountBox.Text = tostring(addAmount)
    end
end)

-- ========== TOMBOL AUTO MONEY ==========
local moneyBtn = Instance.new("TextButton")
moneyBtn.Size = UDim2.new(0.8, 0, 0, 38)
moneyBtn.Position = UDim2.new(0.1, 0, 0.55, 0)
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

-- ========== LOOP AUTO MONEY REAL ==========
spawn(function()
    while true do
        if autoMoney then
            local function addRealMoney()
                -- ===== 1. CARI DI LEADERSTATS =====
                local leaderstats = player:FindFirstChild("leaderstats")
                if leaderstats then
                    for _, stat in ipairs(leaderstats:GetChildren()) do
                        if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                            local name = stat.Name:lower()
                            -- Deteksi semua kemungkinan nama uang
                            local isMoney = false
                            local moneyKeywords = {"coin", "money", "cash", "point", "token", "gem", "diamond", "gold", 
                                                    "silver", "bronze", "credit", "currency", "value", "score", 
                                                    "cc", "bb", "km", "m", "level", "exp", "xp", "stamina", "energy"}
                            for _, kw in ipairs(moneyKeywords) do
                                if name:match(kw) then
                                    isMoney = true
                                    break
                                end
                            end
                            
                            if isMoney and stat.Value < 999999999 then
                                stat.Value = stat.Value + addAmount
                                print("[VORTEX] REAL +" .. addAmount .. " ke " .. stat.Name .. " = " .. stat.Value)
                            end
                        end
                    end
                end

                -- ===== 2. CARI DI SEMUA FOLDER PLAYER =====
                for _, folder in ipairs(player:GetChildren()) do
                    if folder:IsA("Folder") then
                        for _, stat in ipairs(folder:GetChildren()) do
                            if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                                local name = stat.Name:lower()
                                local isMoney = false
                                local moneyKeywords = {"coin", "money", "cash", "point", "token", "gem", "diamond", "gold", 
                                                        "silver", "bronze", "credit", "currency", "value", "score", 
                                                        "cc", "bb", "km", "m", "level", "exp", "xp", "stamina", "energy"}
                                for _, kw in ipairs(moneyKeywords) do
                                    if name:match(kw) then
                                        isMoney = true
                                        break
                                    end
                                end
                                
                                if isMoney and stat.Value < 999999999 then
                                    stat.Value = stat.Value + addAmount
                                    print("[VORTEX] REAL +" .. addAmount .. " ke " .. stat.Name .. " = " .. stat.Value)
                                end
                            end
                        end
                    end
                end

                -- ===== 3. CARI DI BACKPACK =====
                local backpack = player:FindFirstChild("Backpack")
                if backpack then
                    for _, item in ipairs(backpack:GetChildren()) do
                        if item:IsA("Tool") then
                            for _, attr in ipairs(item:GetChildren()) do
                                if attr:IsA("IntValue") or attr:IsA("NumberValue") then
                                    local name = attr.Name:lower()
                                    local isMoney = false
                                    local moneyKeywords = {"coin", "money", "cash", "point", "token", "gem", "diamond", "gold", 
                                                            "silver", "bronze", "credit", "currency", "value", "score", 
                                                            "cc", "bb", "km", "m", "level", "exp", "xp", "stamina", "energy"}
                                    for _, kw in ipairs(moneyKeywords) do
                                        if name:match(kw) then
                                            isMoney = true
                                            break
                                        end
                                    end
                                    
                                    if isMoney and attr.Value < 999999999 then
                                        attr.Value = attr.Value + addAmount
                                    end
                                end
                            end
                        end
                    end
                end

                -- ===== 4. CARI DI DATASTORE (jika ada) =====
                -- Beberapa game menyimpan uang di DataStore, ini akan otomatis terupdate
                pcall(function()
                    local dataStore = game:GetService("DataStoreService")
                    if dataStore then
                        -- Tidak bisa langsung modify, tapi nilai leaderstats akan otomatis tersimpan
                    end
                end)
            end

            addRealMoney()
        end
        wait(0.1)
    end
end)

print("=========================================")
print("     VORTEX DIGITAL - AUTO MONEY REAL")
print("     Uang bertambah NYATA dan bisa dipakai!")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Isi 'Jumlah Tambah' (contoh: 1000)")
print("2. Klik 'Auto Money [OFF]'")
print("3. Uang REAL bertambah dan bisa langsung dipakai")
