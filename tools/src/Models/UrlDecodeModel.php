<?php
class UrlDecodeModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function decode($input) {
        if ($input === null || $input === '') return ['error' => 'No input provided'];
        try {
            $decoded = urldecode($input);
            return [
                'original' => $input,
                'decoded' => $decoded,
                'message' => $decoded === $input ? 'No changes made' : 'Success'
            ];
        } catch (Exception $e) {
            return ['error' => 'Failed to process input.'];
        }
    }
}