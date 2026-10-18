<?php

namespace OPNsense\ControlledBurn;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // Core's cache_safe() versions asset URLs by core's own index.php
        // mtime, which a plugin upgrade doesn't change - browsers then keep
        // a stale topology.js/css after upgrading the plugin. Version our
        // assets by their own mtimes instead.
        $mtimes = '';
        foreach (['js/ControlledBurn/topology.js', 'css/ControlledBurn/topology.css'] as $asset) {
            $mtimes .= (string)@filemtime('/usr/local/opnsense/www/' . $asset);
        }
        $this->view->cbAssetVersion = substr(md5($mtimes), 0, 12);
        $this->view->cbBuild = self::buildLabel();
        $this->view->pick('OPNsense/ControlledBurn/index');
    }

    /**
     * "0.2 · a74670b" from the package's version file (written by the
     * plugins build), so a screenshot shows which build it came from.
     * Installs copied straight from src/ (scripts/deploy.sh) have no such
     * file and say so.
     */
    private static function buildLabel()
    {
        $info = json_decode((string)@file_get_contents('/usr/local/opnsense/version/controlledburn'), true);
        if (!is_array($info) || empty($info['product_version'])) {
            return 'development build';
        }
        $label = $info['product_version'];
        if (!empty($info['product_hash'])) {
            $label .= " \u{00b7} " . substr($info['product_hash'], 0, 7);
        }
        return $label;
    }
}
