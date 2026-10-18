<?php

namespace OPNsense\ControlledBurn\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\ControlledBurn\QuietSave;

/**
 * Saved graph layout: node centre positions, kept per layout ('star' or
 * 'columns'), each replaced as a whole.
 */
class LayoutController extends ApiMutableModelControllerBase
{
    use QuietSave;

    protected static $internalModelName = 'controlledburn';
    protected static $internalModelClass = '\OPNsense\ControlledBurn\ControlledBurn';

    /**
     * Limits on what's stored in config.xml, which the whole firewall loads
     * and backs up: a user granted only this page mustn't be able to bloat
     * it. Far above real use (the graph stops at 500 devices).
     */
    private const MAX_POSITIONS = 2000;
    /** node ids: "firewall", "wan", "device:<mac or IP address>" */
    private const NODE_ID = '/^[A-Za-z0-9:._-]{1,200}$/';
    private const LAYOUTS = ['star', 'columns'];

    /** the layout a request is about; unknown values mean columns */
    private static function layoutName($value)
    {
        return in_array((string)$value, self::LAYOUTS, true) ? (string)$value : 'columns';
    }

    public function getAction()
    {
        $result = [];
        foreach ($this->getModel()->positions->iterateItems() as $position) {
            $result[] = [
                'node_id' => (string)$position->node_id,
                'node_type' => (string)$position->node_type,
                'x' => (int)(string)$position->x,
                'y' => (int)(string)$position->y,
                // positions saved before layouts existed are columns ones
                'layout' => self::layoutName((string)$position->layout),
            ];
        }
        return ['positions' => $result];
    }

    /**
     * Replace one layout's saved positions in one call (POST positions +
     * layout; other layouts are untouched). The frontend always posts its
     * complete position set rather than per-node updates, so a full
     * clear-and-rebuild avoids round-tripping the model's internal row
     * UUIDs to the client.
     */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error_msg' => 'Must be called via POST'];
        }
        $updates = $this->request->getPost('positions');
        if (!is_array($updates)) {
            return ['status' => 'failed', 'error_msg' => 'positions must be an array'];
        }
        if (count($updates) > self::MAX_POSITIONS) {
            return [
                'status' => 'failed',
                'error_msg' => sprintf(
                    'layout not saved: %d node positions is more than the %d ControlledBurn stores',
                    count($updates),
                    self::MAX_POSITIONS
                ),
            ];
        }
        return $this->replace($updates, self::layoutName($this->request->getPost('layout')));
    }

    /**
     * Forget one layout's saved positions (POST layout): its nodes return
     * to their default places. The other layout is untouched.
     */
    public function resetAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error_msg' => 'Must be called via POST'];
        }
        return $this->replace([], self::layoutName($this->request->getPost('layout')));
    }

    private function replace(array $updates, $layout)
    {
        // fail before taking the lock or touching the model
        $this->throwReadOnly();
        Config::getInstance()->lock();
        $model = $this->getModel();

        $stale = [];
        foreach ($model->positions->iterateItems() as $uuid => $position) {
            if (self::layoutName((string)$position->layout) === $layout) {
                $stale[] = $uuid;
            } elseif ((string)$position->layout === '') {
                $position->layout = 'columns'; // saved before layouts existed
            }
        }
        foreach ($stale as $uuid) {
            $model->positions->del($uuid);
        }
        $skipped = [];
        foreach ($updates as $update) {
            if (!is_array($update) || empty($update['node_id']) || empty($update['node_type'])) {
                continue;
            }
            $id = (string)$update['node_id'];
            if (!preg_match(self::NODE_ID, $id)) {
                // save the rest; report it so an unexpected id format shows up
                $skipped[] = substr($id, 0, 60);
                continue;
            }
            $node = $model->positions->add();
            $node->node_id = $update['node_id'];
            $node->node_type = $update['node_type'];
            $node->x = (int)($update['x'] ?? 0);
            $node->y = (int)($update['y'] ?? 0);
            $node->layout = $layout;
        }
        $result = $this->saveQuietly();
        if (!empty($skipped)) {
            $result['skipped'] = $skipped;
        }
        return $result;
    }
}
