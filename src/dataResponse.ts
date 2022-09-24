export interface DataResponse {
    toArrayBuffer(): Promise<ArrayBuffer>;
}

export class StandardDataResponse {
    private readonly _data: ArrayBuffer;
    constructor(data: ArrayBuffer) {
        this._data = data;
    }
    toArrayBuffer(): ArrayBuffer {
        return this._data;
    }
}
