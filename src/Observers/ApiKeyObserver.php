<?php

namespace Ejarnutowski\LaravelApiKey\Observers;

use Illuminate\Support\Facades\Hash;
use Ejarnutowski\LaravelApiKey\Models\ApiKey;

class ApiKeyObserver
{
	public function creating(ApiKey $apiKey)
	{
		if ($apiKey->secret) {
			$apiKey->secret = Hash::make($apiKey->secret);
		}
	}
}
