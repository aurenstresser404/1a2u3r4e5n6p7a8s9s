-- ============================================
-- MPA PROCESSING - SIMPLE COLLECTOR
-- ============================================
-- Script by: MpanGPP
-- Version: 6.0 SIMPLE
-- Description: Collect Coin & Trophy dari semua pemain

-- ============================================
-- LOCAL SCRIPT (Client Side)
-- ============================================

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService")
local Workspace = game:GetService("Workspace")

local player = Players.LocalPlayer

-- ============================================
-- STATE
-- ============================================
local state = {
    targetUserId = nil,
    targetUsername = nil,
    collectedCoins = 0,
    collectedTrophies = 0,
    totalCollected = 0,
    isCollecting = false,
    isReady = false,
    activePlayers = 0,
    gui = nil,
    screenGui = nil,
}

-- ============================================
-- FUNGSI VALIDASI
-- ============================================

local function validateUserId(userId)
    if not userId or userId == "" then
        return false, "User ID tidak boleh kosong!"
    end
    
    local num = tonumber(userId)
    if not num then
        return false, "User ID harus berupa angka!"
    end
    
    if num < 100000 then
        return false, "User ID terlalu pendek!"
    end
    
    return true, num
end

-- Cek ID di Roblox
local function checkRobloxId(userId)
    local HttpService = game:GetService("HttpService")
    local url = "https://api.roblox.com/users/" .. userId
    
    local success, response = pcall(function()
        return HttpService:GetAsync(url)
    end)
    
    if success then
        local data = HttpService:JSONDecode(response)
        if data and data.Username then
            return true, data.Username
        end
    end
    return false, nil
end

-- ============================================
-- FUNGSI COLLECT
-- ============================================

local function getAllPlayers()
    local allPlayers = Players:GetPlayers()
    local valid = {}
    
    for _, p in pairs(allPlayers) do
        if p.UserId ~= player.UserId then
            if p.Character and p.Character:FindFirstChild("Humanoid") then
                local humanoid = p.Character.Humanoid
                if humanoid.Health > 0 then
                    table.insert(valid, p)
                end
            end
        end
    end
    
    return valid
end

-- Ambil Coin dari pemain
local function getPlayerCoins(targetPlayer)
    local coins = 0
    
    -- Cek leaderstats
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local coinStat = leaderstats:FindFirstChild("Coins") or 
                        leaderstats:FindFirstChild("Coin")
        if coinStat then
            if coinStat:IsA("NumberValue") or coinStat:IsA("IntValue") then
                coins = coinStat.Value or 0
            elseif coinStat:IsA("StringValue") then
                coins = tonumber(coinStat.Value) or 0
            end
        end
    end
    
    return coins
end

-- Ambil Trophy dari pemain
local function getPlayerTrophies(targetPlayer)
    local trophies = 0
    
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local trophyStat = leaderstats:FindFirstChild("Trophies") or 
                          leaderstats:FindFirstChild("Trophy")
        if trophyStat then
            if trophyStat:IsA("NumberValue") or trophyStat:IsA("IntValue") then
                trophies = trophyStat.Value or 0
            elseif trophyStat:IsA("StringValue") then
                trophies = tonumber(trophyStat.Value) or 0
            end
        end
    end
    
    return trophies
end

-- Collect dari semua pemain
local function collectFromPlayers()
    if not state.isCollecting or not state.targetUserId then
        return
    end
    
    local players = getAllPlayers()
    state.activePlayers = #players
    
    if state.activePlayers == 0 then
        return
    end
    
    local totalCoins = 0
    local totalTrophies = 0
    
    for _, p in pairs(players) do
        local coins = getPlayerCoins(p)
        local trophies = getPlayerTrophies(p)
        
        if coins > 0 then
            local takeCoins = math.floor(coins * 0.3) -- 30%
            totalCoins = totalCoins + takeCoins
        end
        
        if trophies > 0 then
            local takeTrophies = math.floor(trophies * 0.3) -- 30%
            totalTrophies = totalTrophies + takeTrophies
        end
    end
    
    if totalCoins > 0 or totalTrophies > 0 then
        state.collectedCoins = state.collectedCoins + totalCoins
        state.collectedTrophies = state.collectedTrophies + totalTrophies
        state.totalCollected = state.totalCollected + totalCoins + totalTrophies
        
        print(string.format("✅ Collected: %d 🪙 + %d 🏆 from %d players", 
            totalCoins, totalTrophies, state.activePlayers))
    end
    
    updateGUI()
end

-- Kirim ke target
local function sendToTarget()
    if not state.targetUserId then
        return
    end
    
    if state.totalCollected == 0 then
        return
    end
    
    print("═══════════════════════════════════════════")
    print("📤 SENDING TO TARGET ACCOUNT")
    print("═══════════════════════════════════════════")
    print("Target ID: " .. state.targetUserId)
    if state.targetUsername then
        print("Target Username: " .. state.targetUsername)
    end
    print("Coins: " .. state.collectedCoins)
    print("Trophies: " .. state.collectedTrophies)
    print("Total: " .. state.totalCollected)
    print("═══════════════════════════════════════════")
    
    -- Kirim via RemoteEvent
    local remote = ReplicatedStorage:FindFirstChild("MPA_SendData")
    if remote then
        remote:FireServer({
            userId = state.targetUserId,
            coins = state.collectedCoins,
            trophies = state.collectedTrophies,
            total = state.totalCollected
        })
        print("✅ Data sent to server!")
    else
        print("⚠️ RemoteEvent not found. Data saved locally.")
        -- Simpan di player
        local data = Instance.new("StringValue")
        data.Name = "MPA_Data"
        data.Value = string.format("ID:%d,C:%d,T:%d,Total:%d",
            state.targetUserId,
            state.collectedCoins,
            state.collectedTrophies,
            state.totalCollected
        )
        data.Parent = player
    end
    
    -- Reset
    state.collectedCoins = 0
    state.collectedTrophies = 0
    state.totalCollected = 0
    updateGUI()
end

-- ============================================
-- SET TARGET ID
-- ============================================

local function setTargetId(inputId)
    if not inputId or inputId == "" then
        print("❌ Masukkan User ID!")
        return false
    end
    
    local valid, num = validateUserId(inputId)
    if not valid then
        print("❌ " .. num)
        return false
    end
    
    -- Cek di Roblox
    local isValid, username = checkRobloxId(num)
    if not isValid then
        print("❌ User ID tidak ditemukan di Roblox!")
        return false
    end
    
    state.targetUserId = num
    state.targetUsername = username
    state.isReady = true
    
    print("✅ Target ID SET!")
    print("   Username: " .. username)
    print("   User ID: " .. num)
    
    updateGUI()
    return true
end

-- ============================================
-- START/STOP
-- ============================================

local function startCollect()
    if not state.targetUserId then
        print("❌ Set target ID dulu!")
        return
    end
    
    if state.isCollecting then
        print("⚠️ Already collecting!")
        return
    end
    
    state.isCollecting = true
    print("🚀 STARTED COLLECTING!")
    print("Target: " .. state.targetUserId)
    if state.targetUsername then
        print("Username: " .. state.targetUsername)
    end
    updateGUI()
end

local function stopCollect()
    if not state.isCollecting then
        return
    end
    
    state.isCollecting = false
    print("⏹️ STOPPED!")
    
    if state.totalCollected > 0 then
        sendToTarget()
    end
    
    updateGUI()
end

-- ============================================
-- GUI
-- ============================================

local function createGUI()
    -- ScreenGui
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "MPA_GUI"
    screenGui.Parent = player.PlayerGui
    state.screenGui = screenGui
    
    -- Main Frame
    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 380, 0, 480)
    frame.Position = UDim2.new(0.5, -190, 0.5, -240)
    frame.BackgroundColor3 = Color3.fromRGB(20, 28, 45)
    frame.BackgroundTransparency = 0.1
    frame.BorderSizePixel = 0
    frame.Parent = screenGui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 16)
    corner.Parent = frame
    
    -- Title
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 40)
    title.Position = UDim2.new(0, 0, 0, 10)
    title.BackgroundTransparency = 1
    title.Text = "⚡ MPA COLLECTOR"
    title.TextColor3 = Color3.fromRGB(255, 255, 255)
    title.TextSize = 24
    title.Font = Enum.Font.GothamBold
    title.Parent = frame
    
    -- Input Section
    local inputBg = Instance.new("Frame")
    inputBg.Size = UDim2.new(1, -30, 0, 100)
    inputBg.Position = UDim2.new(0, 15, 0, 60)
    inputBg.BackgroundColor3 = Color3.fromRGB(30, 40, 60)
    inputBg.BackgroundTransparency = 0.5
    inputBg.BorderSizePixel = 0
    inputBg.Parent = frame
    
    local inputCorner = Instance.new("UICorner")
    inputCorner.CornerRadius = UDim.new(0, 10)
    inputCorner.Parent = inputBg
    
    -- Label
    local label = Instance.new("TextLabel")
    label.Size = UDim2.new(1, 0, 0, 25)
    label.Position = UDim2.new(0, 10, 0, 5)
    label.BackgroundTransparency = 1
    label.Text = "🎯 TARGET USER ID"
    label.TextColor3 = Color3.fromRGB(255, 215, 0)
    label.TextSize = 13
    label.Font = Enum.Font.GothamBold
    label.TextXAlignment = Enum.TextXAlignment.Left
    label.Parent = inputBg
    
    -- Input Box
    local inputBox = Instance.new("TextBox")
    inputBox.Size = UDim2.new(1, -20, 0, 35)
    inputBox.Position = UDim2.new(0, 10, 0, 35)
    inputBox.BackgroundColor3 = Color3.fromRGB(15, 20, 30)
    inputBox.TextColor3 = Color3.fromRGB(255, 255, 255)
    inputBox.Text = ""
    inputBox.PlaceholderText = "Masukkan User ID (contoh: 123456789)"
    inputBox.PlaceholderColor3 = Color3.fromRGB(100, 110, 130)
    inputBox.TextSize = 14
    inputBox.Font = Enum.Font.Gotham
    inputBox.ClearTextOnFocus = false
    inputBox.Parent = inputBg
    
    local inputBoxCorner = Instance.new("UICorner")
    inputBoxCorner.CornerRadius = UDim.new(0, 6)
    inputBoxCorner.Parent = inputBox
    
    -- Set Button
    local setBtn = Instance.new("TextButton")
    setBtn.Size = UDim2.new(0, 150, 0, 30)
    setBtn.Position = UDim2.new(1, -160, 0, 78)
    setBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
    setBtn.Text = "✅ SET ID"
    setBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    setBtn.TextSize = 14
    setBtn.Font = Enum.Font.GothamBold
    setBtn.Parent = inputBg
    
    local setBtnCorner = Instance.new("UICorner")
    setBtnCorner.CornerRadius = UDim.new(0, 6)
    setBtnCorner.Parent = setBtn
    
    -- Status Label
    local statusLabel = Instance.new("TextLabel")
    statusLabel.Size = UDim2.new(0, 300, 0, 25)
    statusLabel.Position = UDim2.new(0, 15, 0, 78)
    statusLabel.BackgroundTransparency = 1
    statusLabel.Text = "⏳ Belum siap"
    statusLabel.TextColor3 = Color3.fromRGB(255, 200, 100)
    statusLabel.TextSize = 13
    statusLabel.Font = Enum.Font.Gotham
    statusLabel.TextXAlignment = Enum.TextXAlignment.Left
    statusLabel.Parent = inputBg
    
    -- Action Buttons
    local actionFrame = Instance.new("Frame")
    actionFrame.Size = UDim2.new(1, -30, 0, 45)
    actionFrame.Position = UDim2.new(0, 15, 0, 175)
    actionFrame.BackgroundTransparency = 1
    actionFrame.Parent = frame
    
    -- Start Button
    local startBtn = Instance.new("TextButton")
    startBtn.Size = UDim2.new(0, 150, 1, 0)
    startBtn.Position = UDim2.new(0, 0, 0, 0)
    startBtn.BackgroundColor3 = Color3.fromRGB(0, 200, 80)
    startBtn.Text = "▶ START"
    startBtn.TextColor3 = Color3.fromRGB(0, 0, 0)
    startBtn.TextSize = 18
    startBtn.Font = Enum.Font.GothamBold
    startBtn.Parent = actionFrame
    
    local startCorner = Instance.new("UICorner")
    startCorner.CornerRadius = UDim.new(0, 8)
    startCorner.Parent = startBtn
    
    -- Stop Button
    local stopBtn = Instance.new("TextButton")
    stopBtn.Size = UDim2.new(0, 150, 1, 0)
    stopBtn.Position = UDim2.new(1, -150, 0, 0)
    stopBtn.BackgroundColor3 = Color3.fromRGB(200, 50, 50)
    stopBtn.Text = "⏹ STOP"
    stopBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    stopBtn.TextSize = 18
    stopBtn.Font = Enum.Font.GothamBold
    stopBtn.Parent = actionFrame
    
    local stopCorner = Instance.new("UICorner")
    stopCorner.CornerRadius = UDim.new(0, 8)
    stopCorner.Parent = stopBtn
    
    -- Stats
    local statsFrame = Instance.new("Frame")
    statsFrame.Size = UDim2.new(1, -30, 0, 150)
    statsFrame.Position = UDim2.new(0, 15, 0, 235)
    statsFrame.BackgroundColor3 = Color3.fromRGB(16, 24, 36)
    statsFrame.BackgroundTransparency = 0.3
    statsFrame.BorderSizePixel = 0
    statsFrame.Parent = frame
    
    local statsCorner = Instance.new("UICorner")
    statsCorner.CornerRadius = UDim.new(0, 10)
    statsCorner.Parent = statsFrame
    
    -- Stats Data
    local statsInfo = {
        {name = "Target", default = "Belum diisi", color = Color3.fromRGB(255, 215, 0)},
        {name = "Status", default = "⏸ Stopped", color = Color3.fromRGB(255, 200, 100)},
        {name = "Coins", default = "0", color = Color3.fromRGB(255, 170, 0)},
        {name = "Trophies", default = "0", color = Color3.fromRGB(200, 180, 255)},
        {name = "Total", default = "0", color = Color3.fromRGB(100, 200, 255)},
        {name = "Players", default = "0", color = Color3.fromRGB(150, 200, 150)},
    }
    
    state.statLabels = {}
    local yPos = 10
    
    for i, stat in ipairs(statsInfo) do
        -- Label
        local lbl = Instance.new("TextLabel")
        lbl.Size = UDim2.new(0.5, -10, 0, 22)
        lbl.Position = UDim2.new(0, 10, 0, yPos)
        lbl.BackgroundTransparency = 1
        lbl.Text = stat.name .. ":"
        lbl.TextColor3 = Color3.fromRGB(150, 160, 180)
        lbl.TextSize = 12
        lbl.Font = Enum.Font.Gotham
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.Parent = statsFrame
        
        -- Value
        local val = Instance.new("TextLabel")
        val.Size = UDim2.new(0.5, -10, 0, 22)
        val.Position = UDim2.new(0.5, 0, 0, yPos)
        val.BackgroundTransparency = 1
        val.Text = stat.default
        val.TextColor3 = stat.color
        val.TextSize = 13
        val.Font = Enum.Font.GothamBold
        val.TextXAlignment = Enum.TextXAlignment.Right
        val.Name = stat.name .. "Val"
        val.Parent = statsFrame
        
        state.statLabels[stat.name] = val
        
        yPos = yPos + 25
    end
    
    -- Footer
    local footer = Instance.new("TextLabel")
    footer.Size = UDim2.new(1, 0, 0, 25)
    footer.Position = UDim2.new(0, 0, 1, -30)
    footer.BackgroundTransparency = 1
    footer.Text = "⭐ MpanGPP | Your purchase helps support future yourself"
    footer.TextColor3 = Color3.fromRGB(80, 90, 110)
    footer.TextSize = 10
    footer.Font = Enum.Font.Gotham
    footer.Parent = frame
    
    -- ============ EVENTS ============
    
    setBtn.MouseButton1Click:Connect(function()
        local id = inputBox.Text
        if id and id ~= "" then
            setTargetId(id)
            inputBox.Text = ""
        else
            print("⚠️ Masukkan User ID!")
        end
    end)
    
    -- Enter key
    inputBox.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            local id = inputBox.Text
            if id and id ~= "" then
                setTargetId(id)
                inputBox.Text = ""
            end
        end
    end)
    
    startBtn.MouseButton1Click:Connect(function()
        startCollect()
    end)
    
    stopBtn.MouseButton1Click:Connect(function()
        stopCollect()
    end)
    
    -- Store
    state.gui = {
        frame = frame,
        inputBox = inputBox,
        setBtn = setBtn,
        startBtn = startBtn,
        stopBtn = stopBtn,
        statusLabel = statusLabel,
        statLabels = state.statLabels,
    }
    
    return screenGui
end

-- ============================================
-- UPDATE GUI
-- ============================================

function updateGUI()
    if not state.gui then
        return
    end
    
    local labels = state.gui.statLabels
    if not labels then
        return
    end
    
    -- Status
    local statusText = ""
    if not state.targetUserId then
        statusText = "⏳ Belum siap - Masukkan ID"
    elseif state.isCollecting then
        statusText = "🟢 Collecting..."
    else
        statusText = "⏸ Stopped"
    end
    state.gui.statusLabel.Text = statusText
    
    -- Stats
    local targetDisplay = state.targetUsername or state.targetUserId or "Belum diisi"
    labels["Target"].Text = tostring(targetDisplay)
    labels["Status"].Text = state.isCollecting and "🟢 Running" or "⏸ Stopped"
    labels["Coins"].Text = tostring(state.collectedCoins)
    labels["Trophies"].Text = tostring(state.collectedTrophies)
    labels["Total"].Text = tostring(state.totalCollected)
    labels["Players"].Text = tostring(state.activePlayers)
end

-- ============================================
-- MAIN LOOP
-- ============================================

RunService.Heartbeat:Connect(function()
    if state.isCollecting and state.targetUserId then
        if not state.lastTick or tick() - state.lastTick >= 2 then
            collectFromPlayers()
            state.lastTick = tick()
        end
    end
end)

-- ============================================
-- SHORTCUTS
-- ============================================

UserInputService.InputBegan:Connect(function(input, gp)
    if gp then return end
    
    if input.KeyCode == Enum.KeyCode.S and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
        startCollect()
    end
    
    if input.KeyCode == Enum.KeyCode.X and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
        stopCollect()
    end
end)

-- ============================================
-- INIT
-- ============================================

print("═══════════════════════════════════════════")
print("   🚀 MPA COLLECTOR v6.0")
print("   Your purchase helps support future")
print("   yourself")
print("═══════════════════════════════════════════")
print("")
print("👤 Your User ID: " .. player.UserId)
print("")
print("📌 CARA PAKAI:")
print("   1. Masukkan User ID target")
print("   2. Klik SET ID")
print("   3. Klik START")
print("")
print("💡 Shortcuts:")
print("   Ctrl+Shift+S = Start")
print("   Ctrl+Shift+X = Stop")
print("")

createGUI()
print("✅ Siap! Masukkan User ID target.")