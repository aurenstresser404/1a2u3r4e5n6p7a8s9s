-- ============================================
-- VORTEX DIGITAL
-- Versi 3.0 - Auto Win + Auto Duplicate Coin + Auto Collect Trophy + Speed Walk + Auto Catch Pet
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

local autoEnabled = true
local collectCooldown = 0.1
local trophyCache = {}
local vortexVersion = "3.0"

-- ========== 1. SPEED WALK ==========
local function setMaxSpeed()
    if humanoid then
        humanoid.WalkSpeed = 100
        humanoid.JumpPower = 80
    end
end
setMaxSpeed()
player.CharacterAdded:Connect(function(newChar)
    character = newChar
    humanoid = character:WaitForChild("Humanoid")
    root = character:WaitForChild("HumanoidRootPart")
    setMaxSpeed()
end)

-- ========== 2. AUTO WIN ==========
local function findWinPart()
    for _, obj in ipairs(workspace:GetDescendants()) do
        if obj:IsA("Part") and (
            obj.Name:lower():find("win") or 
            obj.Name:lower():find("finish") or 
            obj.Name:lower():find("end") or
            obj.Name:lower():find("goal")
        ) then
            return obj
        end
    end
    return nil
end

local function autoWin()
    if not autoEnabled then return end
    local winPart = findWinPart()
    if winPart and root then
        root.CFrame = winPart.CFrame + Vector3.new(0, 3, 0)
    end
end

-- ========== 3. AUTO DUPLICATE COIN ==========
local function setupCoinDuplication()
    local leaderstats = player:FindFirstChild("leaderstats")
    if not leaderstats then
        leaderstats = Instance.new("Folder")
        leaderstats.Name = "leaderstats"
        leaderstats.Parent = player
    end

    local coins = leaderstats:FindFirstChild("Coins") or leaderstats:FindFirstChild("Coin") or leaderstats:FindFirstChild("Money")
    if not coins then
        coins = Instance.new("IntValue")
        coins.Name = "Coins"
        coins.Value = 0
        coins.Parent = leaderstats
    end

    coins:GetPropertyChangedSignal("Value"):Connect(function()
        if not autoEnabled then return end
        if coins.Value > 0 and coins.Value < 999999999 then
            task.wait(0.05)
            coins.Value = coins.Value * 2
        end
    end)

    game:GetService("RunService").Heartbeat:Connect(function()
        if not autoEnabled then return end
        if coins and coins.Value > 0 and coins.Value < 999999999 then
            coins.Value = coins.Value * 2
        end
    end)
end
setupCoinDuplication()

-- ========== 4. AUTO COLLECT TROPHY ==========
local function getAllTrophies()
    local trophies = {}
    for _, obj in ipairs(workspace:GetDescendants()) do
        if obj:IsA("Part") or obj:IsA("Model") or obj:IsA("Tool") then
            local name = obj.Name:lower()
            if name:find("trophy") or name:find("piala") or name:find("cup") or name:find("medal") or name:find("achievement") then
                table.insert(trophies, obj)
            end
        end
    end
    return trophies
end

local function autoCollectTrophies()
    if not autoEnabled then return end
    local trophies = getAllTrophies()
    for _, trophy in ipairs(trophies) do
        if trophyCache[trophy] then
            goto continue
        end
        local targetCFrame = nil
        if trophy:IsA("Part") then
            targetCFrame = trophy.CFrame
        elseif trophy:IsA("Model") then
            local primary = trophy:FindFirstChild("HumanoidRootPart") or trophy:FindFirstChild("Head") or trophy:FindFirstChild("Part")
            if primary then
                targetCFrame = primary.CFrame
            end
        elseif trophy:IsA("Tool") then
            targetCFrame = trophy.Handle.CFrame
        end
        if targetCFrame and root then
            root.CFrame = targetCFrame + Vector3.new(0, 2, 0)
            trophyCache[trophy] = true
            task.wait(collectCooldown)
        end
        ::continue::
    end
end

-- ========== 5. AUTO CATCH PET ==========
local function getAllPets()
    local pets = {}
    for _, obj in ipairs(workspace:GetDescendants()) do
        local name = obj.Name:lower()
        if obj:IsA("Model") or obj:IsA("Part") then
            if name:find("pet") or name:find("animal") or name:find("egg") or name:find("monster") or name:find("creature") then
                if obj:FindFirstChild("Humanoid") or obj:FindFirstChild("Health") then
                    table.insert(pets, obj)
                end
            end
        end
    end
    return pets
end

local function autoCatchPet()
    if not autoEnabled then return end
    local pets = getAllPets()
    for _, pet in ipairs(pets) do
        if pet and pet:IsA("Model") then
            local targetPart = pet:FindFirstChild("HumanoidRootPart") or pet:FindFirstChild("Head") or pet:FindFirstChild("Part") or pet.PrimaryPart
            if targetPart then
                root.CFrame = targetPart.CFrame + Vector3.new(0, 2, 0)
                task.wait(0.05)
                local click = pet:FindFirstChild("ClickDetector")
                if click then
                    click:Click()
                end
                local remote = pet:FindFirstChild("CatchRemote") or game:GetService("ReplicatedStorage"):FindFirstChild("PetCatch")
                if remote and remote:IsA("RemoteEvent") then
                    remote:FireServer(pet)
                end
            end
        end
    end
end

-- ========== 6. LOOP UTAMA ==========
game:GetService("RunService").Heartbeat:Connect(function()
    if autoEnabled then
        autoWin()
        autoCollectTrophies()
        autoCatchPet()
    end
end)

-- ========== 7. TOGGLE ON/OFF (Tekan F) ==========
game:GetService("UserInputService").InputBegan:Connect(function(input, gameProcessed)
    if gameProcessed then return end
    if input.KeyCode == Enum.KeyCode.F then
        autoEnabled = not autoEnabled
        print("VORTEX DIGITAL | Auto mode: " .. tostring(autoEnabled))
        game:GetService("StarterGui"):SetCore("SendNotification", {
            Title = "VORTEX DIGITAL",
            Text = "Status: " .. (autoEnabled and "ON" or "OFF"),
            Duration = 2
        })
    end
end)

-- ========== 8. RESET CACHE SAAT RESPAWN ==========
player.CharacterAdded:Connect(function(newChar)
    character = newChar
    humanoid = character:WaitForChild("Humanoid")
    root = character:WaitForChild("HumanoidRootPart")
    trophyCache = {}
    setMaxSpeed()
end)

-- ========== 9. SPLASH SCREEN ==========
print("=========================================")
print("     VORTEX DIGITAL v" .. vortexVersion .. " LOADED")
print("     Auto Win | Auto Duplicate Coin")
print("     Auto Collect Trophy | Speed Walk")
print("     Auto Catch Pet")
print("=========================================")
print("Press F to toggle ON/OFF")
