<?php

namespace Ejarnutowski\LaravelApiKey\Observers;

use Illuminate\Support\Facades\Hash;
use Ejarnutowski\LaravelApiKey\Models\ApiKey;

class ApiKeyObserver
{
	public function creating(ApiKey $apiKey)
	{
		$apiKey->secret = Hash::make($apiKey->secret);
	}
}