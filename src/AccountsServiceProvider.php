<?php
namespace Blimp\Accounts;

use Pimple\ServiceProviderInterface;
use Pimple\Container;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class AccountsServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                if ($api->offsetExists('dataaccess.mongoodm.mappings')) {
                    $api->extend('dataaccess.mongoodm.mappings', function ($mappings, $api) {
                        $mappings[] = ['dir' => __DIR__ . '/Documents', 'prefix' => 'Blimp\\Accounts\\Documents\\'];

                        return $mappings;
                    });
                }
            }

            return $status;
        });
    }
}
