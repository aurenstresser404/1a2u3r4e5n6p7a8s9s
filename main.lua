-- ============================================
-- VORTEX FAST CLIMB TOWER - AUTO CLAIM REWARD
-- Manjat cepat + auto claim piala & coin hasil climb
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL ==========
local fastClimbEnabled = false
local normalSpeed = 16
local climbSpeed = 500
local climbUpForce = 80

-- ========== FUNGSI DETEKSI CLIMB ==========
local function isClimbing()
    if not root then return false end
    local raycastParams = RaycastParams.new()
    raycastParams.FilterDescendantsInstances = {character}
    raycastParams.FilterType = Enum.RaycastFilterType.Blacklist
    
    local origin = root.Position
    local direction = root.CFrame.LookVector * 5
    local rayResult = workspace:Raycast(origin, direction, raycastParams)
    
    if rayResult then
        local normal = rayResult.Normal
        local angle = math.deg(math.acos(normal:Dot(Vector3.new(0, 1, 0))))
        if angle > 70 and angle < 110 then
            return true, normal
        end
    end
    return false, nil
end

-- ========== AUTO CLAIM SEMUA REWARD (PIALA + COIN + DLL) ==========
local function claimAllRewards()
    for _, obj in ipairs(workspace:GetDescendants()) do
        -- Deteksi objek reward: piala, coin, token, reward, chest, gift, dll
        if obj:IsA("Part") or obj:IsA("Model") or obj:IsA("Tool") then
            local name = obj.Name:lower()
            local isReward = false
            
            -- Daftar keyword reward
            local rewardKeywords = {
                "piala", "trophy", "cup", "medal", "reward", "prize",
                "coin", "token", "gem", "diamond", "gold", "silver",
                "chest", "gift", "present", "box", "crate",
                "win", "victory", "complete", "finish", "done"
            }
            
            for _, kw in ipairs(rewardKeywords) do
                if name:match(kw) then
                    isReward = true
                    break
                end
            end
            
            if isReward then
                local target = obj:IsA("Part") and obj or 
                                obj:FindFirstChild("HumanoidRootPart") or 
                                obj:FindFirstChild("Head") or 
                                obj:FindFirstChild("Part") or 
                                obj.PrimaryPart or obj
                
                if target and root then
                    -- Teleport ke reward
                    root.CFrame = target.CFrame + Vector3.new(0, 2, 0)
                    wait(0.02)
                    
                    -- Klik ClickDetector jika ada
                    local click = obj:FindFirstChild("ClickDetector") or target:FindFirstChild("ClickDetector")
                    if click and click:IsA("ClickDetector") then
                        click:Click()
                        print("[VORTEX] Claimed reward: " .. obj.Name)
                    end
                    
                    -- ProximityPrompt jika ada
                    local prompt = obj:FindFirstChild("ProximityPrompt") or target:FindFirstChild("ProximityPrompt")
                    if prompt and prompt:IsA("ProximityPrompt") then
                        prompt:InputHoldStart()
                        wait(0.05)
                        prompt:InputHoldEnd()
                        print("[VORTEX] Claimed reward via prompt: " .. obj.Name)
                    end
                    
                    -- Klik tombol GUI reward jika ada
                    for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                        if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                            local txt = btn.Text:lower()
                            if txt:match("claim") or txt:match("collect") or txt:match("take") or txt:match("reward") then
                                btn:Click()
                                wait(0.02)
                            end
                        end
                    end
                end
            end
        end
    end
end

-- ========== FUNGSI AUTO FAST CLIMB + CLAIM ==========
local function autoFastClimb()
    if not fastClimbEnabled or not humanoid or not root then return end
    
    local climbing, normal = isClimbing()
    
    if climbing then
        -- Saat di tower → kecepatan tinggi + dorongan ke atas
        humanoid.WalkSpeed = climbSpeed
        humanoid.JumpPower = 50
        
        -- Velocity dorong ke atas
        local currentVel = root.Velocity
        root.Velocity = Vector3.new(currentVel.X * 0.5, climbUpForce, currentVel.Z * 0.5) + (normal * -20)
        root.CFrame = CFrame.lookAt(root.Position, root.Position + normal * -1)
        
        -- ===== CLAIM SEMUA REWARD SAAT CLIMB =====
        claimAllRewards()
        
    else
        -- Saat di tanah → normal
        humanoid.WalkSpeed = normalSpeed
        humanoid.JumpPower = 50
    end
end

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexFastClimb"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 250, 0, 130)
frame.Position = UDim2.new(0.5, -125, 0.5, -65)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 25)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 35)
title.BackgroundColor3 = Color3.fromRGB(25, 25, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX FAST CLIMB"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Tombol Toggle
local fastClimbBtn = Instance.new("TextButton")
fastClimbBtn.Size = UDim2.new(0.8, 0, 0, 40)
fastClimbBtn.Position = UDim2.new(0.1, 0, 0.4, 0)
fastClimbBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
fastClimbBtn.BackgroundTransparency = 0.2
fastClimbBtn.Text = "Fast Climb + Auto Claim [OFF]"
fastClimbBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
fastClimbBtn.TextScaled = true
fastClimbBtn.Font = Enum.Font.GothamBold
fastClimbBtn.BorderSizePixel = 1
fastClimbBtn.BorderColor3 = Color3.fromRGB(0, 100, 200)
fastClimbBtn.Parent = frame

fastClimbBtn.MouseButton1Click:Connect(function()
    fastClimbEnabled = not fastClimbEnabled
    fastClimbBtn.Text = fastClimbEnabled and "Fast Climb + Auto Claim [ON]" or "Fast Climb + Auto Claim [OFF]"
    fastClimbBtn.BackgroundColor3 = fastClimbEnabled and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
    print("[VORTEX] Fast Climb + Auto Claim: " .. (fastClimbEnabled and "ON" or "OFF"))
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

-- ========== LOOP UTAMA ==========
game:GetService("RunService").Heartbeat:Connect(function()
    autoFastClimb()
end)

print("=========================================")
print("     VORTEX FAST CLIMB TOWER")
print("     Fast Climb 500 + Auto Claim Reward")
print("     Piala kemenangan + coin otomatis ke claim")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Klik tombol untuk mengaktifkan")
print("2. Saat di tower → climb cepat + auto claim semua reward")
print("3. Saat di tanah → speed normal 16")
