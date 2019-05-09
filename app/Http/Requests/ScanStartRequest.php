<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ScanStartRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'url'            => 'required|string',
            'dangerLevel'    => 'integer|min:0|max:10',
            'callbackurls'   => 'array',
            'userAgent'      => 'string'
        ];
    }

    /**
     * Custom message for validation
     *
     * @return array
     */
    public function messages()
    {
        return [
            'url.required' => 'URL is required!'
        ];
    }
}
