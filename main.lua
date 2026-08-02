-- ============================================
-- VORTEX ALL IN ONE - NO KEY SYSTEM
-- Gabungan Semua Fitur: Auto Buy | Auto Claim | Auto Climb | Auto Coins | Auto Egg | Auto Farm | Auto Hatch | Auto Win | Big Jump | Fast Climb | Money Boost | Teleport | dll
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE ==========
local showMenu = true
local autoBuy = false
local autoClaim = false
local autoClimb = false
local autoCoins = false
local autoEgg = false
local autoFarm = false
local autoHatch = false
local autoWin = false
local bigJump = false
local fastClimb = false
local moneyBoost = false
local teleport = false

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexAllInOne"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

-- ========== FRAME UTAMA ==========
local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 350, 0, 500)
frame.Position = UDim2.new(0.5, -175, 0.5, -250)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 25)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- ========== TITLE BAR ==========
local titleBar = Instance.new("Frame")
titleBar.Size = UDim2.new(1, 0, 0, 40)
titleBar.BackgroundColor3 = Color3.fromRGB(25, 25, 50)
titleBar.BackgroundTransparency = 0.3
titleBar.Parent = frame

local title = Instance.new("TextLabel")
title.Size = UDim2.new(0.6, 0, 1, 0)
title.Position = UDim2.new(0.05, 0, 0, 0)
title.BackgroundTransparency = 1
title.Text = "VORTEX ALL IN ONE"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = titleBar

-- ========== TOMBOL CLOSE MENU ==========
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0, 35, 0, 35)
closeBtn.Position = UDim2.new(0.85, 0, 0.02, 0)
closeBtn.BackgroundColor3 = Color3.fromRGB(200, 50, 50)
closeBtn.BackgroundTransparency = 0.2
closeBtn.Text = "✕"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.TextScaled = true
closeBtn.Font = Enum.Font.GothamBold
closeBtn.BorderSizePixel = 1
closeBtn.BorderColor3 = Color3.fromRGB(150, 50, 50)
closeBtn.Parent = titleBar

closeBtn.MouseButton1Click:Connect(function()
    showMenu = not showMenu
    scroll.Visible = showMenu
    statusBar.Visible = showMenu
    frame.Size = showMenu and UDim2.new(0, 350, 0, 500) or UDim2.new(0, 350, 0, 45)
end)

-- ========== SCROLL ==========
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -50)
scroll.Position = UDim2.new(0, 5, 0, 42)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 550)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 4)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI TOMBOL TOGGLE ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.9, 0, 0, 35)
    btn.Position = UDim2.new(0.05, 0, 0, 0)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.Gotham
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

-- ========== SEMUA FITUR ==========

-- 1. Auto Buy
toggleButton("Auto Buy", function() return autoBuy end, function(v)
    autoBuy = v
    spawn(function()
        while autoBuy do
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") and btn.Text:lower():match("buy") then
                    btn:Click()
                    wait(0.05)
                end
            end
            wait(0.5)
        end
    end)
end)

-- 2. Auto Claim
toggleButton("Auto Claim", function() return autoClaim end, function(v)
    autoClaim = v
    spawn(function()
        while autoClaim do
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") and (btn.Text:lower():match("claim") or btn.Text:lower():match("collect")) then
                    btn:Click()
                    wait(0.05)
                end
            end
            wait(0.5)
        end
    end)
end)

-- 3. Auto Climb
toggleButton("Auto Climb", function() return autoClimb end, function(v)
    autoClimb = v
    spawn(function()
        while autoClimb do
            if humanoid then
                humanoid.Jump = true
                humanoid.WalkSpeed = 50
            end
            wait(0.1)
        end
    end)
end)

-- 4. Auto Coins
toggleButton("Auto Coins", function() return autoCoins end, function(v)
    autoCoins = v
    spawn(function()
        while autoCoins do
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        if stat.Value > 0 and stat.Value < 999999999 then
                            stat.Value = stat.Value * 2
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- 5. Auto Egg
toggleButton("Auto Egg", function() return autoEgg end, function(v)
    autoEgg = v
    spawn(function()
        while autoEgg do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") or obj:IsA("ProximityPrompt") then
                    local p = obj.Parent
                    if p and p.Name:lower():match("egg") then
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
            wait(0.5)
        end
    end)
end)

-- 6. Auto Farm
toggleButton("Auto Farm", function() return autoFarm end, function(v)
    autoFarm = v
    spawn(function()
        while autoFarm do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") and obj.Name:lower():match("farm") then
                    if root then
                        root.CFrame = obj.CFrame + Vector3.new(0, 2, 0)
                        wait(0.1)
                        local click = obj:FindFirstChild("ClickDetector")
                        if click then click:Click() end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- 7. Auto Hatch
toggleButton("Auto Hatch", function() return autoHatch end, function(v)
    autoHatch = v
    spawn(function()
        while autoHatch do
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") and btn.Text:lower():match("hatch") then
                    btn:Click()
                    wait(0.1)
                end
            end
            wait(0.5)
        end
    end)
end)

-- 8. Auto Win
toggleButton("Auto Win", function() return autoWin end, function(v)
    autoWin = v
    spawn(function()
        while autoWin do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") and (obj.Name:lower():match("win") or obj.Name:lower():match("finish")) then
                    if root then
                        root.CFrame = obj.CFrame + Vector3.new(0, 3, 0)
                        wait(0.5)
                    end
                end
            end
            wait(1)
        end
    end)
end)

-- 9. Big Jump
toggleButton("Big Jump", function() return bigJump end, function(v)
    bigJump = v
    if v then
        humanoid.JumpPower = 200
    else
        humanoid.JumpPower = 50
    end
end)

-- 10. Fast Climb
toggleButton("Fast Climb", function() return fastClimb end, function(v)
    fastClimb = v
    spawn(function()
        while fastClimb do
            if humanoid then
                humanoid.WalkSpeed = 100
                humanoid.JumpPower = 150
            end
            wait(0.05)
        end
    end)
end)

-- 11. Money Boost
toggleButton("Money Boost", function() return moneyBoost end, function(v)
    moneyBoost = v
    spawn(function()
        while moneyBoost do
            local leaderstats = player:FindFirstChild("leaderstats")
            if leaderstats then
                for _, stat in ipairs(leaderstats:GetChildren()) do
                    if stat:IsA("IntValue") or stat:IsA("NumberValue") then
                        if stat.Value < 999999999 then
                            stat.Value = stat.Value + 1000
                        end
                    end
                end
            end
            wait(0.5)
        end
    end)
end)

-- 12. Teleport
toggleButton("Teleport", function() return teleport end, function(v)
    teleport = v
    spawn(function()
        while teleport do
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("Part") and obj.Name:lower():match("teleport") then
                    if root then
                        root.CFrame = obj.CFrame + Vector3.new(0, 3, 0)
                        wait(0.5)
                    end
                end
            end
            wait(1)
        end
    end)
end)

-- ========== STATUS BAR ==========
local statusBar = Instance.new("Frame")
statusBar.Size = UDim2.new(1, 0, 0, 30)
statusBar.Position = UDim2.new(0, 0, 1, -30)
statusBar.BackgroundColor3 = Color3.fromRGB(20, 20, 40)
statusBar.BackgroundTransparency = 0.1
statusBar.Parent = frame

local statusText = Instance.new("TextLabel")
statusText.Size = UDim2.new(1, -10, 1, 0)
statusText.Position = UDim2.new(0, 5, 0, 0)
statusText.BackgroundTransparency = 1
statusText.Text = "VORTEX ALL IN ONE | TELEGRAM : @realvortexdigital"
statusText.TextColor3 = Color3.fromRGB(200, 200, 200)
statusText.TextScaled = true
statusText.Font = Enum.Font.Gotham
statusText.TextXAlignment = Enum.TextXAlignment.Left
statusText.Parent = statusBar

-- ========== NOTIFIKASI ==========
print("=========================================")
print("     VORTEX ALL IN ONE - NO KEY SYSTEM")
print("     Auto Buy | Auto Claim | Auto Climb")
print("     Auto Coins | Auto Egg | Auto Farm")
print("     Auto Hatch | Auto Win | Big Jump")
print("     Fast Climb | Money Boost | Teleport")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Klik tombol fitur untuk ON/OFF")
print("2. Klik ✕ untuk close menu")
print("3. Klik title bar untuk show menu kembali")
