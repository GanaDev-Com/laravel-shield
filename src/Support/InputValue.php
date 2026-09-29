<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Support;

/**
 * Nilai argumen/opsi Symfony bertipe `mixed`: bisa string, array, atau null
 * tergantung tipe yang dideklarasikan pada `$signature` dan versi Laravel.
 * Normalisasi disatukan di sini agar `handle()` selalu menerima string yang sudah
 * tervalidasi, tanpa bergantung pada how PhpDoc `argument()` berubah antar versi.
 */
final class InputValue
{
    /**
     * Kembalikan nilai sebagai string non-kosong, atau null bila tidak valid.
     */
    public function string(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
