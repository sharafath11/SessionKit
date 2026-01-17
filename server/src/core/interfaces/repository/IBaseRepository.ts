  import { Document, FilterQuery, UpdateQuery } from "mongoose";

  export interface IBaseRepository<T extends Document, U> {
    create(data: Partial<T>): Promise<U>;
    findAll(filter?: FilterQuery<T>): Promise<U[]>;
    findById(id: string): Promise<U | null>;
    findOne(condition: FilterQuery<T>): Promise<U | null>;
    update(id: string, data: UpdateQuery<T>): Promise<U | null>;
    delete(id: string): Promise<boolean>;
    updateMany(filter: FilterQuery<T>, update: UpdateQuery<T>): Promise<number>;
    handleError(error: unknown, message: string): Error;
    updateOne(filter: FilterQuery<T>, update: UpdateQuery<T>): Promise<U | null>;
    findWithPassword(condition: FilterQuery<T>): Promise<T | null>;
    count(filter?: FilterQuery<T>): Promise<number>;
  }