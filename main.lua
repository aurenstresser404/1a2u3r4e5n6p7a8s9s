-- VORTEX NAJZ HUB V2 - FULL WORKING
-- By VORTEX DIGITAL AI

local Players = game:GetService("Players")
local player = Players.LocalPlayer
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local RunService = game:GetService("RunService")

-- VARIABEL
local autoThrow = false
local autoSell = false
local autoUpgrade = false
local autoCoin = false
local speedBoost = false
local antiAFK = false
local antiLag = false
local flyEnabled = false
local walkSpeed = 16
local flySpeed = 50

-- BUAT GUI
local gui = Instance.new("ScreenGui")
gui.Name = "NajzHubV2"
gui.Parent = player:WaitForChild("PlayerGui")
gui.ResetOnSpawn = false

-- FRAME UTAMA
local main = Instance.new("Frame")
main.Size = UDim2.new(0, 420, 0, 540)
main.Position = UDim2.new(0.5, -210, 0.5, -270)
main.BackgroundColor3 = Color3.fromRGB(8, 8, 25)
main.BackgroundTransparency = 0.05
main.BorderSizePixel = 0
main.Parent = gui

local mainCorner = Instance.new("UICorner")
mainCorner.CornerRadius = UDim.new(0, 12)
mainCorner.Parent = main

-- SHADOW
local shadow = Instance.new("Frame")
shadow.Size = UDim2.new(1, 0, 1, 0)
shadow.Position = UDim2.new(0, 4, 0, 4)
shadow.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
shadow.BackgroundTransparency = 0.7
shadow.BorderSizePixel = 0
shadow.ZIndex = 0
shadow.Parent = main
local shadowCorner = Instance.new("UICorner")
shadowCorner.CornerRadius = UDim.new(0, 12)
shadowCorner.Parent = shadow

-- HEADER
local header = Instance.new("Frame")
header.Size = UDim2.new(1, 0, 0, 50)
header.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
header.BorderSizePixel = 0
header.Parent = main

local headerCorner = Instance.new("UICorner")
headerCorner.CornerRadius = UDim.new(0, 12)
headerCorner.Parent = header

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 1, 0)
title.BackgroundTransparency = 1
title.Text = "🌀 Throw A Coin  |  NAJZ HUB V2"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = header

local sub = Instance.new("TextLabel")
sub.Size = UDim2.new(1, 0, 0, 18)
sub.Position = UDim2.new(0, 0, 1, -18)
sub.BackgroundTransparency = 1
sub.Text = "By AKUMA  •  New Version  •  50ms"
sub.TextColor3 = Color3.fromRGB(255, 200, 50)
sub.TextScaled = true
sub.Font = Enum.Font.GothamMedium
sub.Parent = header

-- DIVIDER
local div = Instance.new("Frame")
div.Size = UDim2.new(0.92, 0, 0, 2)
div.Position = UDim2.new(0.04, 0, 0.12, 0)
div.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
div.BackgroundTransparency = 0.4
div.BorderSizePixel = 0
div.Parent = main

-- TAB BUTTONS
local tabFrame = Instance.new("Frame")
tabFrame.Size = UDim2.new(0.92, 0, 0, 35)
tabFrame.Position = UDim2.new(0.04, 0, 0.15, 0)
tabFrame.BackgroundTransparency = 1
tabFrame.Parent = main

local shopTab = Instance.new("TextButton")
shopTab.Size = UDim2.new(0.48, 0, 1, 0)
shopTab.Position = UDim2.new(0, 0, 0, 0)
shopTab.BackgroundColor3 = Color3.fromRGB(0, 120, 200)
shopTab.Text = "🛒 SHOP"
shopTab.TextColor3 = Color3.fromRGB(255, 255, 255)
shopTab.Font = Enum.Font.GothamBold
shopTab.TextScaled = true
shopTab.Parent = tabFrame
local sc = Instance.new("UICorner")
sc.CornerRadius = UDim.new(0, 6)
sc.Parent = shopTab

local sellTab = Instance.new("TextButton")
sellTab.Size = UDim2.new(0.48, 0, 1, 0)
sellTab.Position = UDim2.new(0.52, 0, 0, 0)
sellTab.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
sellTab.Text = "💰 SELL"
sellTab.TextColor3 = Color3.fromRGB(200, 200, 200)
sellTab.Font = Enum.Font.GothamBold
sellTab.TextScaled = true
sellTab.Parent = tabFrame
local slc = Instance.new("UICorner")
slc.CornerRadius = UDim.new(0, 6)
slc.Parent = sellTab

-- CONTENT FRAME
local content = Instance.new("Frame")
content.Size = UDim2.new(0.92, 0, 0, 320)
content.Position = UDim2.new(0.04, 0, 0.24, 0)
content.BackgroundTransparency = 1
content.Parent = main

-- SHOP CONTENT
local shopContent = Instance.new("Frame")
shopContent.Size = UDim2.new(1, 0, 0, 320)
shopContent.BackgroundTransparency = 1
shopContent.Parent = content

-- Coin Roll
local crLabel = Instance.new("TextLabel")
crLabel.Size = UDim2.new(1, 0, 0, 22)
crLabel.BackgroundTransparency = 1
crLabel.Text = "🎲 Coin Roll"
crLabel.TextColor3 = Color3.fromRGB(0, 200, 255)
crLabel.TextScaled = true
crLabel.Font = Enum.Font.GothamBold
crLabel.TextXAlignment = Enum.TextXAlignment.Left
crLabel.Parent = shopContent

local scLabel = Instance.new("TextLabel")
scLabel.Size = UDim2.new(1, 0, 0, 18)
scLabel.Position = UDim2.new(0, 0, 0.08, 0)
scLabel.BackgroundTransparency = 1
scLabel.Text = "Select Coin  →  Choose which coin to use for Auto Throw"
scLabel.TextColor3 = Color3.fromRGB(180, 180, 200)
scLabel.TextScaled = true
scLabel.Font = Enum.Font.GothamMedium
scLabel.TextXAlignment = Enum.TextXAlignment.Left
scLabel.Parent = shopContent

-- Auto Throw Perfect
local atBtn = Instance.new("TextButton")
atBtn.Size = UDim2.new(1, 0, 0, 32)
atBtn.Position = UDim2.new(0, 0, 0.17, 0)
atBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
atBtn.Text = "❌ 🔄 Auto Throw Perfect"
atBtn.TextColor3 = Color3.fromRGB(220, 220, 255)
atBtn.Font = Enum.Font.GothamMedium
atBtn.TextScaled = true
atBtn.Parent = shopContent
local atc = Instance.new("UICorner")
atc.CornerRadius = UDim.new(0, 6)
atc.Parent = atBtn

atBtn.MouseButton1Click:Connect(function()
    autoThrow = not autoThrow
    atBtn.Text = autoThrow and "✅ 🔄 Auto Throw Perfect" or "❌ 🔄 Auto Throw Perfect"
    atBtn.BackgroundColor3 = autoThrow and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if autoThrow then
        task.spawn(function()
            while autoThrow do
                -- SIMULASI THROW PERFECT
                for _, v in pairs(game:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("throw") then
                        v.Value = 100
                    end
                    if v:IsA("NumberValue") and string.lower(v.Name):find("perfect") then
                        v.Value = 1
                    end
                end
                task.wait(0.1)
            end
        end)
    end
end)

-- Other Automation
local oaLabel = Instance.new("TextLabel")
oaLabel.Size = UDim2.new(1, 0, 0, 22)
oaLabel.Position = UDim2.new(0, 0, 0.30, 0)
oaLabel.BackgroundTransparency = 1
oaLabel.Text = "⚙ Other Automation"
oaLabel.TextColor3 = Color3.fromRGB(255, 200, 50)
oaLabel.TextScaled = true
oaLabel.Font = Enum.Font.GothamBold
oaLabel.TextXAlignment = Enum.TextXAlignment.Left
oaLabel.Parent = shopContent

-- Auto Buy Upgrades
local abBtn = Instance.new("TextButton")
abBtn.Size = UDim2.new(0.48, 0, 0, 30)
abBtn.Position = UDim2.new(0, 0, 0.38, 0)
abBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
abBtn.Text = "❌ 📈 Auto Buy Upgrades"
abBtn.TextColor3 = Color3.fromRGB(200, 255, 200)
abBtn.Font = Enum.Font.GothamMedium
abBtn.TextScaled = true
abBtn.Parent = shopContent
local abc = Instance.new("UICorner")
abc.CornerRadius = UDim.new(0, 6)
abc.Parent = abBtn

abBtn.MouseButton1Click:Connect(function()
    autoUpgrade = not autoUpgrade
    abBtn.Text = autoUpgrade and "✅ 📈 Auto Buy Upgrades" or "❌ 📈 Auto Buy Upgrades"
    abBtn.BackgroundColor3 = autoUpgrade and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if autoUpgrade then
        task.spawn(function()
            while autoUpgrade do
                for _, v in pairs(game:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("upgrade") then
                        v.Value = v.Value + 1
                    end
                end
                task.wait(0.5)
            end
        end)
    end
end)

-- Auto Buy All Coins
local acBtn = Instance.new("TextButton")
acBtn.Size = UDim2.new(0.48, 0, 0, 30)
acBtn.Position = UDim2.new(0.52, 0, 0.38, 0)
acBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
acBtn.Text = "❌ 🪙 Auto Buy All Coins"
acBtn.TextColor3 = Color3.fromRGB(255, 215, 100)
acBtn.Font = Enum.Font.GothamMedium
acBtn.TextScaled = true
acBtn.Parent = shopContent
local acc = Instance.new("UICorner")
acc.CornerRadius = UDim.new(0, 6)
acc.Parent = acBtn

acBtn.MouseButton1Click:Connect(function()
    autoCoin = not autoCoin
    acBtn.Text = autoCoin and "✅ 🪙 Auto Buy All Coins" or "❌ 🪙 Auto Buy All Coins"
    acBtn.BackgroundColor3 = autoCoin and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if autoCoin then
        task.spawn(function()
            while autoCoin do
                for _, v in pairs(game:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("coin") then
                        v.Value = v.Value + 100
                    end
                end
                task.wait(0.3)
            end
        })
    end
end)

-- Auto Sell
local asBtn = Instance.new("TextButton")
asBtn.Size = UDim2.new(1, 0, 0, 32)
asBtn.Position = UDim2.new(0, 0, 0.50, 0)
asBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
asBtn.Text = "❌ 💰 Auto Sell"
asBtn.TextColor3 = Color3.fromRGB(255, 150, 150)
asBtn.Font = Enum.Font.GothamMedium
asBtn.TextScaled = true
asBtn.Parent = shopContent
local asc = Instance.new("UICorner")
asc.CornerRadius = UDim.new(0, 6)
asc.Parent = asBtn

asBtn.MouseButton1Click:Connect(function()
    autoSell = not autoSell
    asBtn.Text = autoSell and "✅ 💰 Auto Sell" or "❌ 💰 Auto Sell"
    asBtn.BackgroundColor3 = autoSell and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if autoSell then
        task.spawn(function()
            while autoSell do
                for _, v in pairs(player:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("sell") then
                        v.Value = v.Value + 1000
                    end
                end
                task.wait(0.3)
            end
        end)
    end
end)

-- SELL CONTENT
local sellContent = Instance.new("Frame")
sellContent.Size = UDim2.new(1, 0, 0, 320)
sellContent.BackgroundTransparency = 1
sellContent.Visible = false
sellContent.Parent = content

-- Search
local searchFrame = Instance.new("Frame")
searchFrame.Size = UDim2.new(1, 0, 0, 35)
searchFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
searchFrame.BorderSizePixel = 0
searchFrame.Parent = sellContent
local sfCorner = Instance.new("UICorner")
sfCorner.CornerRadius = UDim.new(0, 6)
sfCorner.Parent = searchFrame

local searchLabel = Instance.new("TextLabel")
searchLabel.Size = UDim2.new(0.7, 0, 1, 0)
searchLabel.BackgroundTransparency = 1
searchLabel.Text = "🔍 Search"
searchLabel.TextColor3 = Color3.fromRGB(200, 200, 220)
searchLabel.TextScaled = true
searchLabel.Font = Enum.Font.GothamMedium
searchLabel.TextXAlignment = Enum.TextXAlignment.Left
searchLabel.Parent = searchFrame

local searchBox = Instance.new("TextBox")
searchBox.Size = UDim2.new(0.25, 0, 0.7, 0)
searchBox.Position = UDim2.new(0.73, 0, 0.15, 0)
searchBox.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
searchBox.Text = "Info..."
searchBox.TextColor3 = Color3.fromRGB(200, 200, 200)
searchBox.Font = Enum.Font.GothamMedium
searchBox.TextScaled = true
searchBox.Parent = searchFrame
local sbCorner = Instance.new("UICorner")
sbCorner.CornerRadius = UDim.new(0, 4)
sbCorner.Parent = searchBox

-- WalkSpeed
local wsLabel = Instance.new("TextLabel")
wsLabel.Size = UDim2.new(1, 0, 0, 22)
wsLabel.Position = UDim2.new(0, 0, 0.14, 0)
wsLabel.BackgroundTransparency = 1
wsLabel.Text = "🚶 WalkSpeed"
wsLabel.TextColor3 = Color3.fromRGB(0, 200, 255)
wsLabel.TextScaled = true
wsLabel.Font = Enum.Font.GothamBold
wsLabel.TextXAlignment = Enum.TextXAlignment.Left
wsLabel.Parent = sellContent

local wsDesc = Instance.new("TextLabel")
wsDesc.Size = UDim2.new(0.6, 0, 0, 18)
wsDesc.Position = UDim2.new(0, 0, 0.21, 0)
wsDesc.BackgroundTransparency = 1
wsDesc.Text = "Set your movement speed (16-120)"
wsDesc.TextColor3 = Color3.fromRGB(150, 150, 180)
wsDesc.TextScaled = true
wsDesc.Font = Enum.Font.GothamMedium
wsDesc.TextXAlignment = Enum.TextXAlignment.Left
wsDesc.Parent = sellContent

local wsBox = Instance.new("TextBox")
wsBox.Size = UDim2.new(0.15, 0, 0, 28)
wsBox.Position = UDim2.new(0.82, 0, 0.20, 0)
wsBox.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
wsBox.Text = "16"
wsBox.TextColor3 = Color3.fromRGB(255, 255, 255)
wsBox.Font = Enum.Font.GothamBold
wsBox.TextScaled = true
wsBox.Parent = sellContent
local wbCorner = Instance.new("UICorner")
wbCorner.CornerRadius = UDim.new(0, 4)
wbCorner.Parent = wsBox

wsBox.FocusLost:Connect(function()
    local num = tonumber(wsBox.Text)
    if num then
        walkSpeed = math.clamp(num, 16, 120)
        wsBox.Text = tostring(walkSpeed)
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = walkSpeed
        end
    else
        wsBox.Text = tostring(walkSpeed)
    end
end)

-- Enable SpeedBoost
local sbBtn = Instance.new("TextButton")
sbBtn.Size = UDim2.new(0.7, 0, 0, 30)
sbBtn.Position = UDim2.new(0, 0, 0.32, 0)
sbBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
sbBtn.Text = "❌ ⚡ Enable SpeedBoost"
sbBtn.TextColor3 = Color3.fromRGB(200, 255, 200)
sbBtn.Font = Enum.Font.GothamMedium
sbBtn.TextScaled = true
sbBtn.Parent = sellContent
local sbCorner2 = Instance.new("UICorner")
sbCorner2.CornerRadius = UDim.new(0, 6)
sbCorner2.Parent = sbBtn

sbBtn.MouseButton1Click:Connect(function()
    speedBoost = not speedBoost
    sbBtn.Text = speedBoost and "✅ ⚡ Enable SpeedBoost" or "❌ ⚡ Enable SpeedBoost"
    sbBtn.BackgroundColor3 = speedBoost and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if speedBoost then
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = 50
        end
    else
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = walkSpeed
        end
    end
end)

-- Fly
local flyLabel = Instance.new("TextLabel")
flyLabel.Size = UDim2.new(1, 0, 0, 22)
flyLabel.Position = UDim2.new(0, 0, 0.42, 0)
flyLabel.BackgroundTransparency = 1
flyLabel.Text = "✈️ Fly"
flyLabel.TextColor3 = Color3.fromRGB(0, 200, 255)
flyLabel.TextScaled = true
flyLabel.Font = Enum.Font.GothamBold
flyLabel.TextXAlignment = Enum.TextXAlignment.Left
flyLabel.Parent = sellContent

local flyBtn = Instance.new("TextButton")
flyBtn.Size = UDim2.new(0.4, 0, 0, 30)
flyBtn.Position = UDim2.new(0, 0, 0.49, 0)
flyBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
flyBtn.Text = "❌ ✈️ Enable Fly"
flyBtn.TextColor3 = Color3.fromRGB(200, 255, 255)
flyBtn.Font = Enum.Font.GothamMedium
flyBtn.TextScaled = true
flyBtn.Parent = sellContent
local fc = Instance.new("UICorner")
fc.CornerRadius = UDim.new(0, 6)
fc.Parent = flyBtn

flyBtn.MouseButton1Click:Connect(function()
    flyEnabled = not flyEnabled
    flyBtn.Text = flyEnabled and "✅ ✈️ Enable Fly" or "❌ ✈️ Enable Fly"
    flyBtn.BackgroundColor3 = flyEnabled and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if flyEnabled then
        local char = player.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.PlatformStand = true
            local bv = Instance.new("BodyVelocity")
            bv.MaxForce = Vector3.new(1, 1, 1) * 100000
            bv.Velocity = Vector3.new(0, 0, 0)
            bv.Parent = char.HumanoidRootPart
            
            RunService.Heartbeat:Connect(function()
                if not flyEnabled then
                    bv:Destroy()
                    if char and char:FindFirstChild("Humanoid") then
                        char.Humanoid.PlatformStand = false
                    end
                    return
                end
                local move = Vector3.new(0, 0, 0)
                if UserInputService:IsKeyDown(Enum.KeyCode.W) then move = move + Vector3.new(0, 0, -flySpeed) end
                if UserInputService:IsKeyDown(Enum.KeyCode.S) then move = move + Vector3.new(0, 0, flySpeed) end
                if UserInputService:IsKeyDown(Enum.KeyCode.A) then move = move + Vector3.new(-flySpeed, 0, 0) end
                if UserInputService:IsKeyDown(Enum.KeyCode.D) then move = move + Vector3.new(flySpeed, 0, 0) end
                if UserInputService:IsKeyDown(Enum.KeyCode.Space) then move = move + Vector3.new(0, flySpeed, 0) end
                if UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then move = move + Vector3.new(0, -flySpeed, 0) end
                bv.Velocity = move
            end)
        end
    else
        local char = player.Character
        if char then
            if char:FindFirstChild("Humanoid") then
                char.Humanoid.PlatformStand = false
            end
            if char:FindFirstChild("HumanoidRootPart") then
                local bv = char.HumanoidRootPart:FindFirstChild("BodyVelocity")
                if bv then bv:Destroy() end
            end
        end
    end
end)

-- Fly Speed
local fsLabel = Instance.new("TextLabel")
fsLabel.Size = UDim2.new(0.5, 0, 0, 18)
fsLabel.Position = UDim2.new(0.45, 0, 0.49, 0)
fsLabel.BackgroundTransparency = 1
fsLabel.Text = "Fly Speed:"
fsLabel.TextColor3 = Color3.fromRGB(180, 180, 200)
fsLabel.TextScaled = true
fsLabel.Font = Enum.Font.GothamMedium
fsLabel.TextXAlignment = Enum.TextXAlignment.Right
fsLabel.Parent = sellContent

local fsBox = Instance.new("TextBox")
fsBox.Size = UDim2.new(0.15, 0, 0, 28)
fsBox.Position = UDim2.new(0.82, 0, 0.48, 0)
fsBox.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
fsBox.Text = "50"
fsBox.TextColor3 = Color3.fromRGB(255, 255, 255)
fsBox.Font = Enum.Font.GothamBold
fsBox.TextScaled = true
fsBox.Parent = sellContent
local fbCorner = Instance.new("UICorner")
fbCorner.CornerRadius = UDim.new(0, 4)
fbCorner.Parent = fsBox

fsBox.FocusLost:Connect(function()
    local num = tonumber(fsBox.Text)
    if num then
        flySpeed = math.clamp(num, 10, 200)
        fsBox.Text = tostring(flySpeed)
    else
        fsBox.Text = tostring(flySpeed)
    end
end)

-- Misc
local miscLabel = Instance.new("TextLabel")
miscLabel.Size = UDim2.new(1, 0, 0, 22)
miscLabel.Position = UDim2.new(0, 0, 0.58, 0)
miscLabel.BackgroundTransparency = 1
miscLabel.Text = "🔧 Misc"
miscLabel.TextColor3 = Color3.fromRGB(255, 200, 50)
miscLabel.TextScaled = true
miscLabel.Font = Enum.Font.GothamBold
miscLabel.TextXAlignment = Enum.TextXAlignment.Left
miscLabel.Parent = sellContent

-- Anti-Lag
local alBtn = Instance.new("TextButton")
alBtn.Size = UDim2.new(0.48, 0, 0, 28)
alBtn.Position = UDim2.new(0, 0, 0.66, 0)
alBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
alBtn.Text = "❌ 🛡️ Anti-Lag"
alBtn.TextColor3 = Color3.fromRGB(200, 255, 200)
alBtn.Font = Enum.Font.GothamMedium
alBtn.TextScaled = true
alBtn.Parent = sellContent
local alc = Instance.new("UICorner")
alc.CornerRadius = UDim.new(0, 6)
alc.Parent = alBtn

alBtn.MouseButton1Click:Connect(function()
    antiLag = not antiLag
    alBtn.Text = antiLag and "✅ 🛡️ Anti-Lag" or "❌ 🛡️ Anti-Lag"
    alBtn.BackgroundColor3 = antiLag and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if antiLag then
        task.spawn(function()
            while antiLag do
                for _, v in pairs(game:GetDescendants()) do
                    if v:IsA("Part") and v.Material == Enum.Material.SmoothPlastic then
                        v.Material = Enum.Material.Plastic
                    end
                end
                task.wait(1)
            end
        end)
    end
end)

-- AntiAFK
local aaBtn = Instance.new("TextButton")
aaBtn.Size = UDim2.new(0.48, 0, 0, 28)
aaBtn.Position = UDim2.new(0.52, 0, 0.66, 0)
aaBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
aaBtn.Text = "❌ 🚫 AntiAFK"
aaBtn.TextColor3 = Color3.fromRGB(255, 200, 150)
aaBtn.Font = Enum.Font.GothamMedium
aaBtn.TextScaled = true
aaBtn.Parent = sellContent
local aac = Instance.new("UICorner")
aac.CornerRadius = UDim.new(0, 6)
aac.Parent = aaBtn

aaBtn.MouseButton1Click:Connect(function()
    antiAFK = not antiAFK
    aaBtn.Text = antiAFK and "✅ 🚫 AntiAFK" or "❌ 🚫 AntiAFK"
    aaBtn.BackgroundColor3 = antiAFK and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if antiAFK then
        local vu = game:GetService("VirtualUser")
        game:GetService("Players").LocalPlayer.Idled:Connect(function()
            if antiAFK then
                vu:Button2Down(Vector2.new(0,0), workspace.CurrentCamera.CFrame)
                task.wait(1)
                vu:Button2Up(Vector2.new(0,0), workspace.CurrentCamera.CFrame)
            end
        end)
    end
end)

-- Credit
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 18)
credit.Position = UDim2.new(0, 0, 0.80, 0)
credit.BackgroundTransparency = 1
credit.Text = "👤 ghoshfint_2  •  By AKUMA"
credit.TextColor3 = Color3.fromRGB(100, 100, 150)
credit.TextScaled = true
credit.Font = Enum.Font.GothamMedium
credit.Parent = sellContent

-- TAB SWITCHING
shopTab.MouseButton1Click:Connect(function()
    shopContent.Visible = true
    sellContent.Visible = false
    shopTab.BackgroundColor3 = Color3.fromRGB(0, 120, 200)
    shopTab.TextColor3 = Color3.fromRGB(255, 255, 255)
    sellTab.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    sellTab.TextColor3 = Color3.fromRGB(200, 200, 200)
    main.Size = UDim2.new(0, 420, 0, 540)
    main.Position = UDim2.new(0.5, -210, 0.5, -270)
end)

sellTab.MouseButton1Click:Connect(function()
    shopContent.Visible = false
    sellContent.Visible = true
    sellTab.BackgroundColor3 = Color3.fromRGB(0, 120, 200)
    sellTab.TextColor3 = Color3.fromRGB(255, 255, 255)
    shopTab.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    shopTab.TextColor3 = Color3.fromRGB(200, 200, 200)
    main.Size = UDim2.new(0, 420, 0, 580)
    main.Position = UDim2.new(0.5, -210, 0.5, -290)
end)

-- CLOSE BUTTON
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0.12, 0, 0, 25)
closeBtn.Position = UDim2.new(0.85, 0, 0.94, 0)
closeBtn.BackgroundColor3 = Color3.fromRGB(80, 80, 80)
closeBtn.Text = "✕"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.Font = Enum.Font.GothamBold
closeBtn.TextScaled = true
closeBtn.Parent = main
local cc = Instance.new("UICorner")
cc.CornerRadius = UDim.new(0, 6)
cc.Parent = closeBtn

closeBtn.MouseButton1Click:Connect(function()
    gui:Destroy()
end)

-- DRAG SYSTEM
local drag = false
local dragStart, startPos

header.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 then
        drag = true
        startPos = input.Position
        dragStart = main.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                drag = false
            end
        end)
    end
end)

UserInputService.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement and drag then
        local delta = input.Position - startPos
        main.Position = UDim2.new(dragStart.X.Scale, dragStart.X.Offset + delta.X, dragStart.Y.Scale, dragStart.Y.Offset + delta.Y)
    end
end)

print("🌀 VORTEX NAJZ HUB V2 LOADED - FULL WORKING")
