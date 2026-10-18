<?php

function controlledburn_xmlrpc_sync()
{
    $result = array();

    $result[] = array(
        'description' => gettext('ControlledBurn'),
        'section' => 'controlledburn',
        'id' => 'controlledburn',
    );

    return $result;
}
