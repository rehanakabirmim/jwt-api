<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Jobs\SendOtpEmail;

class AuthController extends Controller
{
    // --------------------------
    // 1. Register + send OTP via queue
    // --------------------------
    public function register(Request $request)
    {
        $request->validate([
            'first_name' => 'required|string|max:100',
            'last_name'  => 'required|string|max:100',
            'email'      => 'required|email|unique:users,email',
            'password'   => [
                'required','string','min:8','confirmed',
                'regex:/[a-z]/','regex:/[A-Z]/',
                'regex:/[0-9]/','regex:/[@$!%*#?&]/',
            ],
        ], [
            'password.min'       => 'Password must be at least 8 characters long.',
            'password.confirmed' => 'Password and Confirm Password must match.',
            'password.regex'     => 'Password must include uppercase, lowercase, number, and special character.',
        ]);

        try {
            $otp = rand(100000, 999999);

            $user = User::create([
                'first_name' => $request->first_name,
                'last_name'  => $request->last_name,
                'email'      => $request->email,
                'password'   => Hash::make($request->password),
                'otp'        => $otp,
                'otp_expires_at' => now()->addMinutes(10),
                'otp_resend_count' => 0,
                'otp_last_sent_at' => now(),
            ]);

            // Log registration attempt
            Log::info("User registered", ['user_id' => $user->id, 'email' => $user->email]);

            // Dispatch OTP email via queue
            SendOtpEmail::dispatch($user, $otp);

            return response()->json([
                'message' => 'Registered successfully. OTP has been sent to your email.',
            ], 201);

        } catch (\Exception $e) {
            Log::error("Registration failed", ['error' => $e->getMessage(), 'email' => $request->email]);
            return response()->json([
                'message' => 'Registration failed. Please try again later.',
                'error'   => $e->getMessage(),
            ], 500);
        }
    }

    // --------------------------
    // 2. Verify OTP & auto-login
    // --------------------------
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp'   => 'required|digits:6',
        ]);

        $user = User::where('email', $request->email)
                    ->where('otp', $request->otp)
                    ->where('otp_expires_at', '>=', now())
                    ->first();

        if (!$user) {
            Log::warning("OTP verification failed", ['email' => $request->email]);
            return response()->json(['message' => 'Invalid OTP or OTP expired.'], 401);
        }

        $user->update([
            'otp' => null,
            'otp_expires_at' => null,
            'email_verified_at' => now(),
            'otp_resend_count' => 0,
        ]);

        $token = JWTAuth::fromUser($user);

        Log::info("OTP verified and user logged in", ['user_id' => $user->id, 'email' => $user->email]);

        return response()->json([
            'message' => 'OTP verified. Login successful.',
            'token'   => $token,
        ]);
    }

    // --------------------------
    // 3. Resend OTP with 24h max 3 times
    // --------------------------
    public function resendOtp(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $user = User::where('email', $request->email)->first();
        if (!$user) {
            Log::warning("OTP resend failed - user not found", ['email' => $request->email]);
            return response()->json(['message' => 'User not found.'], 404);
        }

        // Reset count if 24h passed
        if ($user->otp_last_sent_at && $user->otp_last_sent_at->diffInHours(now()) >= 24) {
            $user->otp_resend_count = 0;
        }

        // Max 3 per 24h
        if ($user->otp_resend_count >= 3) {
            Log::warning("OTP resend limit reached", ['user_id' => $user->id, 'email' => $user->email]);
            return response()->json([
                'message' => 'You have reached the maximum OTP resend limit (3 times in 24 hours).'
            ], 429);
        }

        $newOtp = rand(100000, 999999);
        $user->update([
            'otp' => $newOtp,
            'otp_expires_at' => now()->addMinutes(10),
            'otp_resend_count' => $user->otp_resend_count + 1,
            'otp_last_sent_at' => now(),
        ]);

        // Send OTP via queue
        SendOtpEmail::dispatch($user, $newOtp);

        Log::info("OTP resent successfully", ['user_id' => $user->id, 'email' => $user->email]);

        return response()->json([
            'message' => 'OTP resent successfully.'
        ]);
    }

    // --------------------------
    // 4. Login using email + password
    // --------------------------
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            Log::warning("Login failed", ['email' => $request->email]);
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        $token = JWTAuth::fromUser($user);

        Log::info("User logged in", ['user_id' => $user->id, 'email' => $user->email]);

        return response()->json([
            'message' => 'Login successful.',
            'token'   => $token,
        ]);
    }

    // --------------------------
    // 5. Get authenticated user profile
    // --------------------------
    public function profile(Request $request)
    {
        return response()->json($request->user());
    }

    // --------------------------
    // 6. Logout (invalidate JWT)
    // --------------------------
    public function logout(Request $request)
    {
        JWTAuth::invalidate(JWTAuth::getToken());
        Log::info("User logged out", ['user_id' => $request->user()->id, 'email' => $request->user()->email]);
        return response()->json(['message' => 'Successfully logged out.']);
    }
}
 