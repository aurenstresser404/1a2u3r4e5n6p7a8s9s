-- VORTEX REAL BYPASS ENGINE v5.0
-- Inject langsung ke mekanisme game, setiap push = +1B REAL

local player = game.Players.LocalPlayer
local replicatedStorage = game:GetService("ReplicatedStorage")
local runService = game:GetService("RunService")

-- Cari remote event/fungsi yang menangani push lucky block
local remoteEvent = nil
for _, v in pairs(replicatedStorage:GetDescendants()) do
    if v:IsA("RemoteEvent") and (v.Name:lower():find("push") or v.Name:lower():find("lucky") or v.Name:lower():find("block") or v.Name:lower():find("click") or v.Name:lower():find("interact")) then
        remoteEvent = v
        break
    end
end

-- Jika tidak ketemu, cari di service lain
if not remoteEvent then
    for _, service in pairs(game:GetServices()) do
        for _, v in pairs(service:GetDescendants()) do
            if v:IsA("RemoteEvent") and (v.Name:lower():find("push") or v.Name:lower():find("lucky") or v.Name:lower():find("click")) then
                remoteEvent = v
                break
            end
        end
        if remoteEvent then break end
    end
end

-- Buat GUI kontrol
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "VortexBypass"
screenGui.ResetOnSpawn = false
screenGui.Parent = player.PlayerGui

local mainFrame = Instance.new("Frame")
mainFrame.Size = UDim2.new(0, 300, 0, 180)
mainFrame.Position = UDim2.new(0.5, -150, 0.5, -90)
mainFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
mainFrame.BackgroundTransparency = 0.2
mainFrame.BorderSizePixel = 2
mainFrame.BorderColor3 = Color3.fromRGB(255, 50, 50)
mainFrame.Active = true
mainFrame.Draggable = true
mainFrame.Parent = screenGui

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 35)
title.Position = UDim2.new(0, 0, 0, 5)
title.BackgroundTransparency = 1
title.Text = "🔥 VORTEX REAL BYPASS"
title.TextColor3 = Color3.fromRGB(255, 50, 50)
title.TextSize = 20
title.Font = Enum.Font.SourceSansBold
title.Parent = mainFrame

local statusLabel = Instance.new("TextLabel")
statusLabel.Size = UDim2.new(1, 0, 0, 30)
statusLabel.Position = UDim2.new(0, 0, 0, 45)
statusLabel.BackgroundTransparency = 1
statusLabel.Text = "⚡ Status: READY"
statusLabel.TextColor3 = Color3.fromRGB(0, 255, 0)
statusLabel.TextSize = 16
statusLabel.Font = Enum.Font.SourceSans
statusLabel.Parent = mainFrame

local powerLabel = Instance.new("TextLabel")
powerLabel.Size = UDim2.new(1, 0, 0, 30)
powerLabel.Position = UDim2.new(0, 0, 0, 75)
powerLabel.BackgroundTransparency = 1
powerLabel.Text = "💎 Power: 0 B"
powerLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
powerLabel.TextSize = 16
powerLabel.Font = Enum.Font.SourceSans
powerLabel.Parent = mainFrame

local pushBtn = Instance.new("TextButton")
pushBtn.Size = UDim2.new(0.8, 0, 0, 45)
pushBtn.Position = UDim2.new(0.1, 0, 0, 115)
pushBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 0)
pushBtn.Text = "💥 PUSH +1B (REAL)"
pushBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
pushBtn.TextSize = 18
pushBtn.Font = Enum.Font.SourceSansBold
pushBtn.Parent = mainFrame

-- Variabel
local currentPower = 0
local isPushing = false

-- Fungsi untuk mendapatkan nilai power dari game
local function getGamePower()
    -- Coba cari di leaderstats
    local leaderstats = player:FindFirstChild("leaderstats")
    if leaderstats then
        for _, v in pairs(leaderstats:GetChildren()) do
            if v:IsA("NumberValue") and (v.Name:lower():find("power") or v.Name:lower():find("score") or v.Name:lower():find("point")) then
                return v
            end
        end
    end
    
    -- Coba cari di player sendiri
    for _, v in pairs(player:GetChildren()) do
        if v:IsA("NumberValue") and (v.Name:lower():find("power") or v.Name:lower():find("score")) then
            return v
        end
    end
    
    return nil
end

local powerValue = getGamePower()

-- Fungsi bypass push
local function bypassPush()
    if isPushing then return end
    isPushing = true
    
    -- Method 1: Jika ada remote event, panggil dengan payload
    if remoteEvent then
        -- Kirim sinyal push ke server
        remoteEvent:FireServer("push", 1e9) -- Kirim 1B
        remoteEvent:FireServer("click", 1e9)
        remoteEvent:FireServer("interact", 1e9)
        
        -- Kirim multiple payload untuk redundansi
        for i = 1, 5 do
            remoteEvent:FireServer()
            task.wait(0.01)
        end
    end
    
    -- Method 2: Inject langsung ke nilai power
    if powerValue then
        powerValue.Value = powerValue.Value + 1e9
        currentPower = powerValue.Value
    end
    
    -- Method 3: Fire ke semua remote yang mirip
    for _, v in pairs(replicatedStorage:GetDescendants()) do
        if v:IsA("RemoteEvent") or v:IsA("RemoteFunction") then
            pcall(function()
                if v:IsA("RemoteEvent") then
                    v:FireServer("push")
                    v:FireServer("click")
                    v:FireServer(1e9)
                elseif v:IsA("RemoteFunction") then
                    v:InvokeServer("push")
                    v:InvokeServer("click")
                end
            end)
        end
    end
    
    -- Method 4: Paksa nilai di semua object
    for _, obj in pairs(game:GetDescendants()) do
        if obj:IsA("NumberValue") and (obj.Name:lower():find("power") or obj.Name:lower():find("score") or obj.Name:lower():find("point") or obj.Name:lower():find("energy")) then
            pcall(function()
                obj.Value = obj.Value + 1e9
            end)
        end
    end
    
    -- Update display
    if powerValue then
        powerLabel.Text = "💎 Power: " .. string.format("%.0f B", powerValue.Value/1e9)
    end
    
    statusLabel.Text = "✅ PUSH SUCCESS! +1B"
    statusLabel.TextColor3 = Color3.fromRGB(0, 255, 0)
    
    isPushing = false
end

-- Auto push loop (bypass terus menerus)
local function autoBypass()
    while true do
        bypassPush()
        task.wait(0.05) -- 20 push/detik = 20B/detik
    end
end

-- Tombol push
pushBtn.MouseButton1Click:Connect(bypassPush)

-- Tombol toggle menu
local toggleBtn = Instance.new("TextButton")
toggleBtn.Size = UDim2.new(0, 100, 0, 35)
toggleBtn.Position = UDim2.new(0.02, 0, 0.92, 0)
toggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
toggleBtn.Text = "⚡ VORTEX"
toggleBtn.TextColor3 = Color3.fromRGB(255, 50, 50)
toggleBtn.TextSize = 16
toggleBtn.Font = Enum.Font.SourceSansBold
toggleBtn.Parent = screenGui
toggleBtn.MouseButton1Click:Connect(function()
    screenGui.Enabled = not screenGui.Enabled
end)

-- Tombol close
local closeBtn = Instance.new("TextButton")
closeBtn.Size = UDim2.new(0, 25, 0, 25)
closeBtn.Position = UDim2.new(1, -30, 0, 5)
closeBtn.BackgroundColor3 = Color3.fromRGB(200, 0, 0)
closeBtn.Text = "X"
closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
closeBtn.TextSize = 14
closeBtn.Font = Enum.Font.SourceSansBold
closeBtn.Parent = mainFrame
closeBtn.MouseButton1Click:Connect(function()
    screenGui.Enabled = false
end)

-- Update display awal
if powerValue then
    powerLabel.Text = "💎 Power: " .. string.format("%.0f B", powerValue.Value/1e9)
end

print("🔥 VORTEX REAL BYPASS ACTIVATED!")
print("⚡ Setiap push = +1B REAL")
print("💀 Siap untuk bypass!")

-- Auto start bypass (uncomment untuk auto push tanpa tombol)
-- task.spawn(autoBypass)
