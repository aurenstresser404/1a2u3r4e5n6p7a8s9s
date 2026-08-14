-- VORTEX NAJZ HUB V2 - FIXED WORKING
-- By VORTEX DIGITAL AI

local Players = game:GetService("Players")
local player = Players.LocalPlayer
local UIS = game:GetService("UserInputService")

-- BUAT GUI
local gui = Instance.new("ScreenGui")
gui.Name = "NajzHubV2"
gui.Parent = player:WaitForChild("PlayerGui")

-- FRAME UTAMA
local main = Instance.new("Frame")
main.Size = UDim2.new(0, 420, 0, 560)
main.Position = UDim2.new(0.5, -210, 0.5, -280)
main.BackgroundColor3 = Color3.fromRGB(10, 10, 30)
main.BackgroundTransparency = 0.1
main.BorderSizePixel = 0
main.Parent = gui

local mc = Instance.new("UICorner")
mc.CornerRadius = UDim.new(0, 12)
mc.Parent = main

-- HEADER
local header = Instance.new("Frame")
header.Size = UDim2.new(1, 0, 0, 50)
header.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
header.BorderSizePixel = 0
header.Parent = main

local hc = Instance.new("UICorner")
hc.CornerRadius = UDim.new(0, 12)
hc.Parent = header

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

local stc = Instance.new("UICorner")
stc.CornerRadius = UDim.new(0, 6)
stc.Parent = shopTab

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

-- CONTENT
local content = Instance.new("Frame")
content.Size = UDim2.new(0.92, 0, 0, 340)
content.Position = UDim2.new(0.04, 0, 0.24, 0)
content.BackgroundTransparency = 1
content.Parent = main

-- SHOP CONTENT
local shopContent = Instance.new("Frame")
shopContent.Size = UDim2.new(1, 0, 0, 340)
shopContent.BackgroundTransparency = 1
shopContent.Parent = content

-- Fungsi bikin tombol toggle
local function createToggle(parent, y, text, icon, color, callback)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, 0, 0, 32)
    btn.Position = UDim2.new(0, 0, y, 0)
    btn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
    btn.Text = "❌ " .. icon .. " " .. text
    btn.TextColor3 = color or Color3.fromRGB(220, 220, 255)
    btn.Font = Enum.Font.GothamMedium
    btn.TextScaled = true
    btn.Parent = parent
    
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, 6)
    c.Parent = btn
    
    local state = false
    btn.MouseButton1Click:Connect(function()
        state = not state
        btn.Text = state and "✅ " .. icon .. " " .. text or "❌ " .. icon .. " " .. text
        btn.BackgroundColor3 = state and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
        if callback then callback(state) end
    end)
    return btn
end

-- Fungsi bikin tombol sekali tekan
local function createButton(parent, y, text, icon, color, callback)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.48, 0, 0, 30)
    btn.Position = UDim2.new(y, 0, 0, 0)
    btn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
    btn.Text = icon .. " " .. text
    btn.TextColor3 = color or Color3.fromRGB(220, 220, 255)
    btn.Font = Enum.Font.GothamMedium
    btn.TextScaled = true
    btn.Parent = parent
    
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, 6)
    c.Parent = btn
    
    btn.MouseButton1Click:Connect(function()
        if callback then callback(btn) end
    end)
    return btn
end

-- Coin Roll Label
local cr = Instance.new("TextLabel")
cr.Size = UDim2.new(1, 0, 0, 22)
cr.BackgroundTransparency = 1
cr.Text = "🎲 Coin Roll"
cr.TextColor3 = Color3.fromRGB(0, 200, 255)
cr.TextScaled = true
cr.Font = Enum.Font.GothamBold
cr.TextXAlignment = Enum.TextXAlignment.Left
cr.Parent = shopContent

local sc = Instance.new("TextLabel")
sc.Size = UDim2.new(1, 0, 0, 18)
sc.Position = UDim2.new(0, 0, 0.08, 0)
sc.BackgroundTransparency = 1
sc.Text = "Select Coin  →  Choose which coin to use for Auto Throw"
sc.TextColor3 = Color3.fromRGB(180, 180, 200)
sc.TextScaled = true
sc.Font = Enum.Font.GothamMedium
sc.TextXAlignment = Enum.TextXAlignment.Left
sc.Parent = shopContent

-- Auto Throw Perfect
local atState = false
createToggle(shopContent, 0.17, "Auto Throw Perfect", "🔄", Color3.fromRGB(100, 255, 150), function(s)
    atState = s
    if s then
        task.spawn(function()
            while atState do
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

-- Other Automation Label
local oa = Instance.new("TextLabel")
oa.Size = UDim2.new(1, 0, 0, 22)
oa.Position = UDim2.new(0, 0, 0.30, 0)
oa.BackgroundTransparency = 1
oa.Text = "⚙ Other Automation"
oa.TextColor3 = Color3.fromRGB(255, 200, 50)
oa.TextScaled = true
oa.Font = Enum.Font.GothamBold
oa.TextXAlignment = Enum.TextXAlignment.Left
oa.Parent = shopContent

-- Auto Buy Upgrades
local abState = false
local abFrame = Instance.new("Frame")
abFrame.Size = UDim2.new(0.48, 0, 0, 30)
abFrame.Position = UDim2.new(0, 0, 0.38, 0)
abFrame.BackgroundTransparency = 1
abFrame.Parent = shopContent

createButton(abFrame, 0, "Auto Buy Upgrades", "📈", Color3.fromRGB(200, 255, 200), function(btn)
    abState = not abState
    btn.Text = abState and "✅ 📈 Auto Buy Upgrades" or "📈 Auto Buy Upgrades"
    btn.BackgroundColor3 = abState and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if abState then
        task.spawn(function()
            while abState do
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
local acState = false
local acFrame = Instance.new("Frame")
acFrame.Size = UDim2.new(0.48, 0, 0, 30)
acFrame.Position = UDim2.new(0.52, 0, 0.38, 0)
acFrame.BackgroundTransparency = 1
acFrame.Parent = shopContent

createButton(acFrame, 0, "Auto Buy All Coins", "🪙", Color3.fromRGB(255, 215, 100), function(btn)
    acState = not acState
    btn.Text = acState and "✅ 🪙 Auto Buy All Coins" or "🪙 Auto Buy All Coins"
    btn.BackgroundColor3 = acState and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    if acState then
        task.spawn(function()
            while acState do
                for _, v in pairs(game:GetDescendants()) do
                    if v:IsA("NumberValue") and string.lower(v.Name):find("coin") then
                        v.Value = v.Value + 100
                    end
                end
                task.wait(0.3)
            end
        end)
    end
end)

-- Auto Sell
local asState = false
createToggle(shopContent, 0.50, "Auto Sell", "💰", Color3.fromRGB(255, 150, 150), function(s)
    asState = s
    if s then
        task.spawn(function()
            while asState do
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
sellContent.Size = UDim2.new(1, 0, 0, 340)
sellContent.BackgroundTransparency = 1
sellContent.Visible = false
sellContent.Parent = content

-- Search
local sf = Instance.new("Frame")
sf.Size = UDim2.new(1, 0, 0, 35)
sf.BackgroundColor3 = Color3.fromRGB(20, 20, 50)
sf.BorderSizePixel = 0
sf.Parent = sellContent

local sfc = Instance.new("UICorner")
sfc.CornerRadius = UDim.new(0, 6)
sfc.Parent = sf

local sl = Instance.new("TextLabel")
sl.Size = UDim2.new(0.7, 0, 1, 0)
sl.BackgroundTransparency = 1
sl.Text = "🔍 Search"
sl.TextColor3 = Color3.fromRGB(200, 200, 220)
sl.TextScaled = true
sl.Font = Enum.Font.GothamMedium
sl.TextXAlignment = Enum.TextXAlignment.Left
sl.Parent = sf

local sb = Instance.new("TextBox")
sb.Size = UDim2.new(0.25, 0, 0.7, 0)
sb.Position = UDim2.new(0.73, 0, 0.15, 0)
sb.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
sb.Text = "Info..."
sb.TextColor3 = Color3.fromRGB(200, 200, 200)
sb.Font = Enum.Font.GothamMedium
sb.TextScaled = true
sb.Parent = sf

local sbc = Instance.new("UICorner")
sbc.CornerRadius = UDim.new(0, 4)
sbc.Parent = sb

-- WalkSpeed
local ws = Instance.new("TextLabel")
ws.Size = UDim2.new(1, 0, 0, 22)
ws.Position = UDim2.new(0, 0, 0.14, 0)
ws.BackgroundTransparency = 1
ws.Text = "🚶 WalkSpeed"
ws.TextColor3 = Color3.fromRGB(0, 200, 255)
ws.TextScaled = true
ws.Font = Enum.Font.GothamBold
ws.TextXAlignment = Enum.TextXAlignment.Left
ws.Parent = sellContent

local wsd = Instance.new("TextLabel")
wsd.Size = UDim2.new(0.6, 0, 0, 18)
wsd.Position = UDim2.new(0, 0, 0.21, 0)
wsd.BackgroundTransparency = 1
wsd.Text = "Set your movement speed (16-120)"
wsd.TextColor3 = Color3.fromRGB(150, 150, 180)
wsd.TextScaled = true
wsd.Font = Enum.Font.GothamMedium
wsd.TextXAlignment = Enum.TextXAlignment.Left
wsd.Parent = sellContent

local wb = Instance.new("TextBox")
wb.Size = UDim2.new(0.15, 0, 0, 28)
wb.Position = UDim2.new(0.82, 0, 0.20, 0)
wb.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
wb.Text = "16"
wb.TextColor3 = Color3.fromRGB(255, 255, 255)
wb.Font = Enum.Font.GothamBold
wb.TextScaled = true
wb.Parent = sellContent

local wbc = Instance.new("UICorner")
wbc.CornerRadius = UDim.new(0, 4)
wbc.Parent = wb

wb.FocusLost:Connect(function()
    local num = tonumber(wb.Text)
    if num then
        num = math.clamp(num, 16, 120)
        wb.Text = tostring(num)
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = num
        end
    else
        wb.Text = "16"
    end
end)

-- Enable SpeedBoost
local sbState = false
createToggle(sellContent, 0.32, "Enable SpeedBoost", "⚡", Color3.fromRGB(200, 255, 200), function(s)
    sbState = s
    if s then
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = 50
        end
    else
        if player.Character and player.Character:FindFirstChild("Humanoid") then
            player.Character.Humanoid.WalkSpeed = 16
        end
    end
end)

-- Fly
local fly = Instance.new("TextLabel")
fly.Size = UDim2.new(1, 0, 0, 22)
fly.Position = UDim2.new(0, 0, 0.42, 0)
fly.BackgroundTransparency = 1
fly.Text = "✈️ Fly"
fly.TextColor3 = Color3.fromRGB(0, 200, 255)
fly.TextScaled = true
fly.Font = Enum.Font.GothamBold
fly.TextXAlignment = Enum.TextXAlignment.Left
fly.Parent = sellContent

local flyState = false
local flySpeed = 50
local flyBtn = Instance.new("TextButton")
flyBtn.Size = UDim2.new(0.4, 0, 0, 30)
flyBtn.Position = UDim2.new(0, 0, 0.49, 0)
flyBtn.BackgroundColor3 = Color3.fromRGB(25, 25, 55)
flyBtn.Text = "❌ ✈️ Enable Fly"
flyBtn.TextColor3 = Color3.fromRGB(200, 255, 255)
flyBtn.Font = Enum.Font.GothamMedium
flyBtn.TextScaled = true
flyBtn.Parent = sellContent

local fyc = Instance.new("UICorner")
fyc.CornerRadius = UDim.new(0, 6)
fyc.Parent = flyBtn

flyBtn.MouseButton1Click:Connect(function()
    flyState = not flyState
    flyBtn.Text = flyState and "✅ ✈️ Enable Fly" or "❌ ✈️ Enable Fly"
    flyBtn.BackgroundColor3 = flyState and Color3.fromRGB(0, 100, 50) or Color3.fromRGB(25, 25, 55)
    
    if flyState then
        local char = player.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.PlatformStand = true
            local bv = Instance.new("BodyVelocity")
            bv.MaxForce = Vector3.new(1, 1, 1) * 100000
            bv.Velocity = Vector3.new(0, 0, 0)
            bv.Parent = char.HumanoidRootPart
            
            game:GetService("RunService").Heartbeat:Connect(function()
                if not flyState then
                    bv:Destroy()
                    if char and char:FindFirstChild("Humanoid") then
                        char.Humanoid.PlatformStand = false
                    end
                    return
                end
                local move = Vector3.new(0, 0, 0)
                if UIS:IsKeyDown(Enum.KeyCode.W) then move = move + Vector3.new(0, 0, -flySpeed) end
                if UIS:IsKeyDown(Enum.KeyCode.S) then move = move + Vector3.new(0, 0, flySpeed) end
                if UIS:IsKeyDown(Enum.KeyCode.A) then move = move + Vector3.new(-flySpeed, 0, 0) end
                if UIS:IsKeyDown(Enum.KeyCode.D) then move = move + Vector3.new(flySpeed, 0, 0) end
                if UIS:IsKeyDown(Enum.KeyCode.Space) then move = move + Vector3.new(0, flySpeed, 0) end
                if UIS:IsKeyDown(Enum.KeyCode.LeftShift) then move = move + Vector3.new(0, -flySpeed, 0) end
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

-- Fly Speed Box
local fs = Instance.new("TextLabel")
fs.Size = UDim2.new(0.5, 0, 0, 18)
fs.Position = UDim2.new(0.45, 0, 0.49, 0)
fs.BackgroundTransparency = 1
fs.Text = "Fly Speed:"
fs.TextColor3 = Color3.fromRGB(180, 180, 200)
fs.TextScaled = true
fs.Font = Enum.Font.GothamMedium
fs.TextXAlignment = Enum.TextXAlignment.Right
fs.Parent = sellContent

local fbx = Instance.new("TextBox")
fbx.Size = UDim2.new(0.15, 0, 0, 28)
fbx.Position = UDim2.new(0.82, 0, 0.48, 0)
fbx.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
fbx.Text = "50"
fbx.TextColor3 = Color3.fromRGB(255, 255, 255)
fbx.Font = Enum.Font.GothamBold
fbx.TextScaled = true
fbx.Parent = sellContent

local fbc = Instance.new("UICorner")
fbc.CornerRadius = UDim.new(0, 4)
fbc.Parent = fbx

fbx.FocusLost:Connect(function()
    local num = tonumber(fbx.Text)
    if num then
        flySpeed = math.clamp(num, 10, 200)
        fbx.Text = tostring(flySpeed)
    else
        fbx.Text = tostring(flySpeed)
    end
end)

-- Misc
local misc = Instance.new("TextLabel")
misc.Size = UDim2.new(1, 0, 0, 22)
misc.Position = UDim2.new(0, 0, 0.58, 0)
misc.BackgroundTransparency = 1
misc.Text = "🔧 Misc"
misc.TextColor3 = Color3.fromRGB(255, 200, 50)
misc.TextScaled = true
misc.Font = Enum.Font.GothamBold
misc.TextXAlignment = Enum.TextXAlignment.Left
misc.Parent = sellContent

-- Anti-Lag
local alState = false
createToggle(sellContent, 0.66, "Anti-Lag", "🛡️", Color3.fromRGB(200, 255, 200), function(s)
    alState = s
    if s then
        task.spawn(function()
            while alState do
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
local aaState = false
createToggle(sellContent, 0.74, "AntiAFK", "🚫", Color3.fromRGB(255, 200, 150), function(s)
    aaState = s
    if s then
        local vu = game:GetService("VirtualUser")
        game:GetService("Players").LocalPlayer.Idled:Connect(function()
            if aaState then
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
credit.Position = UDim2.new(0, 0, 0.84, 0)
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
    main.Size = UDim2.new(0, 420, 0, 560)
    main.Position = UDim2.new(0.5, -210, 0.5, -280)
end)

sellTab.MouseButton1Click:Connect(function()
    shopContent.Visible = false
    sellContent.Visible = true
    sellTab.BackgroundColor3 = Color3.fromRGB(0, 120, 200)
    sellTab.TextColor3 = Color3.fromRGB(255, 255, 255)
    shopTab.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    shopTab.TextColor3 = Color3.fromRGB(200, 200, 200)
    main.Size = UDim2.new(0, 420, 0, 590)
    main.Position = UDim2.new(0.5, -210, 0.5, -295)
end)

-- CLOSE BUTTON
local close = Instance.new("TextButton")
close.Size = UDim2.new(0.12, 0, 0, 25)
close.Position = UDim2.new(0.85, 0, 0.94, 0)
close.BackgroundColor3 = Color3.fromRGB(80, 80, 80)
close.Text = "✕"
close.TextColor3 = Color3.fromRGB(255, 255, 255)
close.Font = Enum.Font.GothamBold
close.TextScaled = true
close.Parent = main

local cc = Instance.new("UICorner")
cc.CornerRadius = UDim.new(0, 6)
cc.Parent = close

close.MouseButton1Click:Connect(function()
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

UIS.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement and drag then
        local delta = input.Position - startPos
        main.Position = UDim2.new(dragStart.X.Scale, dragStart.X.Offset + delta.X, dragStart.Y.Scale, dragStart.Y.Offset + delta.Y)
    end
end)

print("🌀 VORTEX NAJZ HUB V2 LOADED - WORKING!")
