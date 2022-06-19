<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use Illuminate\Http\JsonResponse;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
// use JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth as JWT;
use Validator;
class TokensController extends Controller
{

    /**
     * Register user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(StoreUserRequest $request)
    {
        $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);
        $token = JWT::fromUser($user);

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user,
            "access_token" => $token

        ], 201);
    }

    /**
     * login user
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        $validator = Validator::make($credentials, [
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'code' => 1,
                'message' => 'Wrong validation',
                'errors' => $validator->errors()
            ], 422);
        }

        $email = $request->input('email');
        $user = User::where('email', '=', $email)->first();
        try {
            // verify the credentials and create a token for the user
            if (! $token = JWT::fromUser($user)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        // if no errors are encountered we can return a JWT
        return response()->json([
            'message' => 'Welcome to directory digital',
            'user' => $user,
            "access_token" => $token
        ], 201);
    }

    /**
     * Logout user
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        // auth()->logout();
        $token = JWT::getToken();
        try {
            JWT::invalidate($token);
            return response()->json([
                'success' => true,
                'message' => 'Logout successful'
            ],200);
        } catch (JWTException $ex) {
            return response()->json([
                'sucess' => false,
                'message' => 'Failed logou, please try again'
            ],422);
        }
        // return response()->json(['message' => 'User successfully logged out.']);
    }

    /**
     * Refresh token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {

        $token = JWT::getToken();
        try{
            $token = JWT::refresh($token);
            return response()->json([
                'sucess' => true,
                'access_token' => $token
            ], 200);
        }catch (TokenExpiredException $ex){
            return response()->json([
                'sucess' => false,
                'message' => 'Volver a iniciar sesion !',
                // 'errors' => $validator->errors()
            ], 422);
        }catch (TokenBlacklistedException $ex){
            return response()->json([
                'sucess' => false,
                'message' => 'Volver a iniciar sesion !',
                // 'errors' => $validator->errors()
            ], 422);
        }
        // return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get user profile.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function profile(Request $request): JsonResponse
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
        $user = JWT::authenticate($request->token);
        if(!$user)
            return response()->json([
                'message' => 'Invalid token / token expired',
            ], 401);
        return response()->json(['user' => $user]);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


}
