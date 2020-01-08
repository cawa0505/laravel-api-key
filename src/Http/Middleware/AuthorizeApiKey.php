<?php

namespace Ejarnutowski\LaravelApiKey\Http\Middleware;

use Closure;
use Ejarnutowski\LaravelApiKey\Models\ApiKey;
use Ejarnutowski\LaravelApiKey\Models\ApiKeyAccessEvent;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

class AuthorizeApiKey
{
    const AUTH_HEADER = 'X-Authorization';
    const AUTH_SECRET = 'X-Authorization-Secret';

    /**
     * Handle the incoming request
     *
     * @param Request $request
     * @param Closure $next
     * @return \Illuminate\Contracts\Routing\ResponseFactory|mixed|\Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next)
    {
        $header = $request->header(self::AUTH_HEADER);
        $secret = $request->header(self::AUTH_SECRET);
        $apiKey = ApiKey::getByKey($header);

        if ($apiKey instanceof ApiKey && $this->testSecretKey($secret, $apiKey)) {
            $this->logAccessEvent($request, $apiKey);
            return $next($request);
        }

        return response([
            'errors' => [[
                'message' => 'Unauthorized'
            ]]
        ], 401);
    }

    /**
     * Test the secret key, but only if it is configured to be used
     *
     * @param string $secret
     * @param ApiKey $apiKey
     * @return boolean
     */
    public function testSecretKey($secret, ApiKey $apiKey) {
        if(config('apikey.enable_secret_key') === true) {
            if($secret && Hash::check($secret, $apiKey->secret)) {
                if (Hash::needsRehash($apiKey->secret)) {
                    $apiKey->secret = $secret;
                    $apiKey->save(); // The ApiKeyObserver will rehash it
                }
                // configured and passes
                return true;
            } else {
                // configured, but failed
                return false;
            }
        } else {
            // not configured
            return true;
        }
    }

    /**
     * Log an API key access event
     *
     * @param Request $request
     * @param ApiKey  $apiKey
     */
    protected function logAccessEvent(Request $request, ApiKey $apiKey)
    {
        $event = new ApiKeyAccessEvent;
        $event->api_key_id = $apiKey->id;
        $event->ip_address = $request->ip();
        $event->url        = $request->fullUrl();
        $event->save();
    }
}
