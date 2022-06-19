<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth as JWT;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;
class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // app()[PermissionRegistrar::class]->forgetCachedPermissions();
        $role = Role::create(['name' => 'Super-Admin']);

        $user = User::create([
            'name' => 'Judith',
            'email' => 'judith@gmail.com',
            'password' => Hash::make('Judith1234')
        ]);
        // $user->assignRole($role);
    }
}
