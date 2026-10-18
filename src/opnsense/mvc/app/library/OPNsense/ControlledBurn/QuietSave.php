<?php

namespace OPNsense\ControlledBurn;

use OPNsense\Core\Config;

/**
 * Save plugin UI state (node layout, audit checks) without creating a
 * configuration history entry.
 *
 * The standard save() makes a backup revision (System -> Configuration ->
 * History) and fires a config-changed event on every call. Dragging nodes or
 * ticking 30 checks would then flood the history - which keeps a limited
 * number of revisions - and push real configuration changes out of it.
 * Config::save(null, false) still writes config.xml (so the state is in any
 * later backup) but skips the backup revision and the event.
 *
 * For use in an ApiMutableModelControllerBase after Config::lock() and
 * changing the model.
 */
trait QuietSave
{
    /**
     * Validate and write the model, or return the validation errors.
     * Releases the config lock either way.
     *
     * @return array {result: "saved"} or {result: "failed", validations}
     */
    protected function saveQuietly()
    {
        $result = $this->validate();
        if (!empty($result['result'])) {
            Config::getInstance()->unlock();
            return $result;
        }
        $this->throwReadOnly();
        $this->getModel()->serializeToConfig();
        Config::getInstance()->save(null, false);
        return ['result' => 'saved'];
    }
}
