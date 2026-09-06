-- ===== VARIABEL GLOBAL =====
local player = game.Players.LocalPlayer
local char = player.Character or player.CharacterAdded:Wait()
local humanoid = char:WaitForChild("Humanoid")
local speedEnabled = false
local speedValue = 80
local originalSpeed = 16
local heartConnection = nil
local menuVisible = true

-- Update karakter saat respawn
player.CharacterAdded:Connect(function(newChar)
    char = newChar
    humanoid = newChar:WaitForChild("Humanoid")
    originalSpeed = humanoid.WalkSpeed or 16
    if speedEnabled then
        humanoid.WalkSpeed = speedValue
    end
end)

-- ===== FUNGSI SPEED LOOP =====
local function startHeartbeat()
    if heartConnection then return end
    heartConnection = game:GetService("RunService").Heartbeat:Connect(function()
        if humanoid and humanoid.Parent and speedEnabled then
            humanoid.WalkSpeed = speedValue
        end
    end)
end

local function stopHeartbeat()
    if heartConnection then
        heartConnection:Disconnect()
        heartConnection = nil
    end
    if humanoid and humanoid.Parent then
        humanoid.WalkSpeed = originalSpeed
    end
end

-- ===== TOGGLE SPEED =====
local function toggleSpeed()
    speedEnabled = not speedEnabled
    if speedEnabled then
        startHeartbeat()
        if humanoid then humanoid.WalkSpeed = speedValue end
    else
        stopHeartbeat()
    end
    return speedEnabled
end

-- ===== FUNGSI BUAT MENU =====
local function createMenu()
    local screen = Instance.new("ScreenGui")
    screen.Name = "SpeedMenuGUI"
    screen.ResetOnSpawn = false

    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 280, 0, 200)
    frame.Position = UDim2.new(0.5, -140, 0.5, -100)
    frame.BackgroundColor3 = Color3.fromRGB(25, 25, 35)
    frame.BorderSizePixel = 1
    frame.BorderColor3 = Color3.fromRGB(100, 100, 255)
    frame.Active = true
    frame.Draggable = true

    -- Title
    local title = Instance.new("TextLabel", frame)
    title.Size = UDim2.new(1, 0, 0, 30)
    title.BackgroundTransparency = 1
    title.Text = "SPEED WALK CONTROL"
    title.TextColor3 = Color3.fromRGB(0, 200, 255)
    title.TextScaled = true

    -- Tombol Close (X) - hancurkan GUI
    local closeBtn = Instance.new("TextButton", frame)
    closeBtn.Size = UDim2.new(0, 30, 0, 30)
    closeBtn.Position = UDim2.new(1, -35, 0, 2)
    closeBtn.Text = "X"
    closeBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    closeBtn.BackgroundColor3 = Color3.fromRGB(150, 0, 0)
    closeBtn.MouseButton1Click:Connect(function()
        menuVisible = false
        frame:Destroy()
        screen:Destroy()
    end)

    -- Tombol Open kembali (jika menu hilang, panggil createMenu lagi)
    -- (akan dijelaskan di bagian akhir)

    -- Tombol Toggle Speed
    local toggleBtn = Instance.new("TextButton", frame)
    toggleBtn.Size = UDim2.new(0, 120, 0, 35)
    toggleBtn.Position = UDim2.new(0, 15, 0, 40)
    toggleBtn.Text = "SPEED OFF"
    toggleBtn.BackgroundColor3 = Color3.fromRGB(200, 50, 50)
    toggleBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    toggleBtn.MouseButton1Click:Connect(function()
        local status = toggleSpeed()
        toggleBtn.Text = status and "SPEED ON" or "SPEED OFF"
        toggleBtn.BackgroundColor3 = status and Color3.fromRGB(50, 200, 50) or Color3.fromRGB(200, 50, 50)
        -- update nilai slider saat toggle
        speedInput.Text = tostring(speedValue)
    end)

    -- Input Speed (TextBox)
    local speedInput = Instance.new("TextBox", frame)
    speedInput.Size = UDim2.new(0, 100, 0, 35)
    speedInput.Position = UDim2.new(0, 150, 0, 40)
    speedInput.Text = tostring(speedValue)
    speedInput.PlaceholderText = "16-250"
    speedInput.BackgroundColor3 = Color3.fromRGB(40, 40, 50)
    speedInput.TextColor3 = Color3.fromRGB(255, 255, 255)
    speedInput.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            local val = tonumber(speedInput.Text)
            if val and val >= 16 and val <= 250 then
                speedValue = val
                if speedEnabled and humanoid then
                    humanoid.WalkSpeed = speedValue
                end
            else
                speedInput.Text = tostring(speedValue)
            end
        end
    end)

    -- Tombol + (naik 5)
    local plusBtn = Instance.new("TextButton", frame)
    plusBtn.Size = UDim2.new(0, 30, 0, 30)
    plusBtn.Position = UDim2.new(0, 255, 0, 42)
    plusBtn.Text = "+"
    plusBtn.BackgroundColor3 = Color3.fromRGB(60, 60, 70)
    plusBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    plusBtn.MouseButton1Click:Connect(function()
        local newVal = speedValue + 5
        if newVal > 250 then newVal = 250 end
        speedValue = newVal
        speedInput.Text = tostring(speedValue)
        if speedEnabled and humanoid then
            humanoid.WalkSpeed = speedValue
        end
    end)

    -- Tombol - (turun 5)
    local minusBtn = Instance.new("TextButton", frame)
    minusBtn.Size = UDim2.new(0, 30, 0, 30)
    minusBtn.Position = UDim2.new(0, 225, 0, 42)
    minusBtn.Text = "-"
    minusBtn.BackgroundColor3 = Color3.fromRGB(60, 60, 70)
    minusBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    minusBtn.MouseButton1Click:Connect(function()
        local newVal = speedValue - 5
        if newVal < 16 then newVal = 16 end
        speedValue = newVal
        speedInput.Text = tostring(speedValue)
        if speedEnabled and humanoid then
            humanoid.WalkSpeed = speedValue
        end
    end)

    -- Label speed range
    local rangeLabel = Instance.new("TextLabel", frame)
    rangeLabel.Size = UDim2.new(0, 250, 0, 20)
    rangeLabel.Position = UDim2.new(0, 15, 0, 80)
    rangeLabel.BackgroundTransparency = 1
    rangeLabel.Text = "Range: 16 (normal) - 250 (max)"
    rangeLabel.TextColor3 = Color3.fromRGB(180, 180, 180)
    rangeLabel.TextSize = 12

    -- Tombol Open kembali (jika menu tertutup, tekan tombol ini untuk memunculkan)
    -- Karena jika menu di-destroy, kita perlu cara memanggil createMenu lagi.
    -- Kita gunakan bind ke tombol di layar utama (misal di StarterGui)
    -- Atau gunakan perintah di chat: /openspeed

    screen.Parent = player.PlayerGui
    menuVisible = true
    return screen
end

-- ===== FUNGSI OPEN MENU (jika tertutup) =====
local function openMenu()
    if menuVisible then
        -- jika sudah ada, jangan buat duplikat
        local existing = player.PlayerGui:FindFirstChild("SpeedMenuGUI")
        if existing then return end
    end
    createMenu()
end

-- ===== BIND KE CHAT COMMAND ATAU TOMBOL GLOBAL =====
-- Opsi 1: Perintah chat "/openspeed"
game:GetService("Players").LocalPlayer.Chatted:Connect(function(msg)
    if msg:lower() == "/openspeed" then
        openMenu()
    end
end)

-- Opsi 2: Buat tombol kecil di pojok layar yang selalu ada
local function createFloatingButton()
    local btnScreen = Instance.new("ScreenGui")
    btnScreen.Name = "FloatingButton"
    btnScreen.ResetOnSpawn = false

    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0, 50, 0, 50)
    btn.Position = UDim2.new(0, 10, 0, 10)
    btn.Text = "⚡"
    btn.TextSize = 24
    btn.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
    btn.TextColor3 = Color3.fromRGB(0, 200, 255)
    btn.Draggable = true
    btn.MouseButton1Click:Connect(function()
        openMenu()
    end)

    btn.Parent = btnScreen
    btnScreen.Parent = player.PlayerGui
end

-- Jalankan
createFloatingButton()
-- Buka menu awal
createMenu()
