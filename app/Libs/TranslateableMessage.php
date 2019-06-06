<?php

namespace App\Libs;

class TranslateableMessage
{
    /**
     * Set id and placeholders for a TranslateableMessage.
     *
     * @param string     $translationStringId
     * @param null|array $placeholders
     */
    public static function get(String $translationStringId, $placeholders = null)
    {
        return [
            'translationStringId' => $translationStringId,
            'placeholders'      => $placeholders,
        ];
    }
}
