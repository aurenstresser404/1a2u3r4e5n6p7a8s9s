-- VORTEX ULTIMATE POWER MENU v3.0
-- One-click unlock 500B + GUI toggle

local player = game.Players.LocalPlayer
local guiService = game:GetService("UserInputService")

-- Buat ScreenGui utama
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexPowerMenu"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

-- Background utama
local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 300, 0, 200)
mainFrame.Position = UDim2.new(0.5, -150, 0.5, -100)
mainFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 30)
mainFrame.BackgroundTransparency = 0.1
mainFrame.BorderSizePixel = 2
mainFrame.BorderColor3 = Color3.fromRGB(0, 200, 255)
mainFrame.Active = true
mainFrame.Draggable = true
mainFrame.Parent = screenGui

-- Tombol close (X)
local closeButton = Instance.new("TextButton")
closeButton.Size = UDim2.new(0, 30, 0, 30)
closeButton.Position = UDim2.new(1, -35, 0, 5)
closeButton.BackgroundColor3 = Color3.fromRGB(200, 30, 30)
closeButton.Text = "✕"
closeButton.TextColor3 = Color3.fromRGB(255, 255, 255)
closeButton.TextSize = 18
closeButton.Font = Enum.Font.SourceSansBold
closeButton.Parent = mainFrame
closeButton.MouseButton1Click:Connect(function()
    screenGui.Enabled = false
end)

-- Judul
local titleLabel = Instance.new("TextLabel")
titleLabel.Size = UDim2.new(1, 0, 0, 40)
titleLabel.Position = UDim2.new(0, 0, 0, 10)
titleLabel.BackgroundTransparency = 1
titleLabel.Text = "⚡ VORTEX POWER ENGINE"
titleLabel.TextColor3 = Color3.fromRGB(0, 200, 255)
titleLabel.TextSize = 22
titleLabel.TextScaled = true
titleLabel.Font = Enum.Font.SourceSansBold
titleLabel.Parent = mainFrame

-- Label power saat ini
local powerLabel = Instance.new("TextLabel")
powerLabel.Size = UDim2.new(1, 0, 0, 40)
powerLabel.Position = UDim2.new(0, 0, 0, 55)
powerLabel.BackgroundTransparency = 1
powerLabel.Text = "Power: 0 B"
powerLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
powerLabel.TextSize = 18
powerLabel.TextScaled = true
powerLabel.Font = Enum.Font.SourceSans
powerLabel.Parent = mainFrame

-- Tombol UNLOCK 500B
local unlockButton = Instance.new("TextButton")
unlockButton.Size = UDim2.new(0.8, 0, 0, 50)
unlockButton.Position = UDim2.new(0.1, 0, 0, 105)
unlockButton.BackgroundColor3 = Color3.fromRGB(0, 180, 80)
unlockButton.Text = "🚀 UNLOCK 500B POWER"
unlockButton.TextColor3 = Color3.fromRGB(255, 255, 255)
unlockButton.TextSize = 20
unlockButton.TextScaled = true
unlockButton.Font = Enum.Font.SourceSansBold
unlockButton.Parent = mainFrame

-- Tombol toggle menu (show/hide) - di luar GUI
local toggleButton = Instance.new("TextButton")
toggleButton.Size = UDim2.new(0, 120, 0, 40)
toggleButton.Position = UDim2.new(0.02, 0, 0.9, 0)
toggleButton.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleButton.Text = "⚡ VORTEX"
toggleButton.TextColor3 = Color3.fromRGB(0, 200, 255)
toggleButton.TextSize = 18
toggleButton.Font = Enum.Font.SourceSansBold
toggleButton.Parent = screenGui
toggleButton.MouseButton1Click:Connect(function()
    screenGui.Enabled = not screenGui.Enabled
end)

-- Variabel power
local power = 0
local targetPower = 500e9
local unlocked = false

-- Fungsi update GUI
local function updatePowerDisplay()
    powerLabel.Text = "Power: " .. string.format("%.2f B", power/1e9)
end

-- Fungsi UNLOCK langsung ke 500B
local function instantUnlock()
    if unlocked then
        powerLabel.Text = "✅ SUDAH UNLOCKED!"
        return
    end
    
    power = targetPower
    unlocked = true
    updatePowerDisplay()
    powerLabel.TextColor3 = Color3.fromRGB(0, 255, 100)
    
    -- Efek visual
    unlockButton.BackgroundColor3 = Color3.fromRGB(0, 255, 100)
    unlockButton.Text = "✅ UNLOCKED!"
    
    -- Trigger event kemenangan
    local victoryFlag = Instance.new("BoolValue")
    victoryFlag.Name = "Power500BUnlocked"
    victoryFlag.Parent = player
    
    print("🎯 500B POWER UNLOCKED!")
    
    -- Efek tambahan: getar frame
    for i = 1, 5 do
        mainFrame.Position = mainFrame.Position + UDim2.new(0, math.random(-3, 3), 0, 0)
        task.wait(0.02)
    end
    mainFrame.Position = UDim2.new(0.5, -150, 0.5, -100)
end

-- Hubungkan tombol unlock
unlockButton.MouseButton1Click:Connect(instantUnlock)

-- Tampilkan menu saat pertama kali
screenGui.Enabled = true
updatePowerDisplay()

print("⚡ VORTEX POWER MENU ACTIVE - Tekan tombol UNLOCK untuk 500B instan!")
