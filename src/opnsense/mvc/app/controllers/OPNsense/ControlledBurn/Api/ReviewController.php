<?php

namespace OPNsense\ControlledBurn\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\ControlledBurn\QuietSave;

/**
 * Audit sign-offs ("checked" edges). Each entry is an edge id plus a
 * fingerprint of what the edge allowed when it was checked, and a short
 * human-readable snapshot of the same. The frontend treats a fingerprint
 * mismatch as "changed since checked" and shows the snapshot next to what
 * the edge allows now, so a stale sign-off can't hide a new hole.
 */
class ReviewController extends ApiMutableModelControllerBase
{
    use QuietSave;

    protected static $internalModelName = 'controlledburn';
    protected static $internalModelClass = '\OPNsense\ControlledBurn\ControlledBurn';

    /** keep snapshots bounded; they're for display only */
    private const SNAPSHOT_MAX = 4000;

    /**
     * Limits on what's stored in config.xml, which the whole firewall loads
     * and backs up: a user granted only this page mustn't be able to bloat
     * it. Each check is a deliberate click, so real use stays far below.
     */
    private const MAX_REVIEWS = 5000;
    /** edge ids: "f:<from>><to>" or "u:<a>|<b>" built from node ids */
    private const EDGE_ID = '/^[A-Za-z0-9:._|>-]{1,300}$/';

    public function getAction()
    {
        $reviews = [];
        $snapshots = [];
        foreach ($this->getModel()->reviews->iterateItems() as $review) {
            $id = (string)$review->edge_id;
            $reviews[$id] = (string)$review->fingerprint;
            $snapshots[$id] = (string)$review->snapshot;
        }
        return ['reviews' => $reviews, 'snapshots' => $snapshots];
    }

    /**
     * POST edge_id + fingerprint (+ optional snapshot) to mark an edge
     * checked, replacing any earlier sign-off for it; or edge_id +
     * checked=0 to clear it.
     */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error_msg' => 'Must be called via POST'];
        }
        $edgeId = (string)$this->request->getPost('edge_id');
        $fingerprint = (string)$this->request->getPost('fingerprint');
        $snapshot = self::cap((string)$this->request->getPost('snapshot', null, ''));
        $checked = (string)$this->request->getPost('checked', null, '1') !== '0';
        if ($edgeId === '') {
            return ['status' => 'failed', 'error_msg' => 'edge_id is required'];
        }
        if (!preg_match(self::EDGE_ID, $edgeId)) {
            return ['status' => 'failed', 'error_msg' => 'not saved: unexpected edge id "' . substr($edgeId, 0, 60) . '"'];
        }

        $this->throwReadOnly();
        Config::getInstance()->lock();
        $model = $this->getModel();
        $this->remove($model, $edgeId);
        if ($checked && count($model->reviews->getNodes()) >= self::MAX_REVIEWS) {
            Config::getInstance()->unlock();
            return [
                'status' => 'failed',
                'error_msg' => sprintf(
                    'not saved: %d edges are already checked, the most ControlledBurn stores. Clear some checks first',
                    self::MAX_REVIEWS
                ),
            ];
        }
        if ($checked) {
            $node = $model->reviews->add();
            $node->edge_id = $edgeId;
            $node->fingerprint = $fingerprint;
            $node->snapshot = $snapshot;
        }
        return $this->saveQuietly();
    }

    /**
     * Clear every sign-off.
     */
    public function resetAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error_msg' => 'Must be called via POST'];
        }
        $this->throwReadOnly();
        Config::getInstance()->lock();
        $this->remove($this->getModel(), null);
        return $this->saveQuietly();
    }

    /**
     * First SNAPSHOT_MAX characters, without splitting a UTF-8 character.
     * (PCRE's /u rather than mbstring, which OPNsense doesn't guarantee.)
     */
    private static function cap($text)
    {
        if (preg_match('/^.{0,' . self::SNAPSHOT_MAX . '}/su', $text, $m)) {
            return $m[0];
        }
        return substr($text, 0, self::SNAPSHOT_MAX); // not valid UTF-8
    }

    /** delete sign-offs for one edge, or all of them ($edgeId null) */
    private function remove($model, $edgeId)
    {
        // collect first: don't delete from the list while iterating it
        $stale = [];
        foreach ($model->reviews->iterateItems() as $uuid => $review) {
            if ($edgeId === null || (string)$review->edge_id === $edgeId) {
                $stale[] = $uuid;
            }
        }
        foreach ($stale as $uuid) {
            $model->reviews->del($uuid);
        }
    }
}
