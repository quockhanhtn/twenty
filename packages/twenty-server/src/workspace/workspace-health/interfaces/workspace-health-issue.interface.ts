import { WorkspaceTableStructure } from 'src/workspace/workspace-health/interfaces/workspace-table-definition.interface';

import { FieldMetadataEntity } from 'src/metadata/field-metadata/field-metadata.entity';
import { ObjectMetadataEntity } from 'src/metadata/object-metadata/object-metadata.entity';

export enum WorkspaceHealthIssueType {
  MISSING_TABLE = 'MISSING_TABLE',
  TABLE_NAME_SHOULD_BE_CUSTOM = 'TABLE_NAME_SHOULD_BE_CUSTOM',
  TABLE_TARGET_TABLE_NAME_NOT_VALID = 'TABLE_TARGET_TABLE_NAME_NOT_VALID',
  TABLE_DATA_SOURCE_ID_NOT_VALID = 'TABLE_DATA_SOURCE_ID_NOT_VALID',
  TABLE_NAME_NOT_VALID = 'TABLE_NAME_NOT_VALID',
  MISSING_COLUMN = 'MISSING_COLUMN',
  MISSING_INDEX = 'MISSING_INDEX',
  MISSING_FOREIGN_KEY = 'MISSING_FOREIGN_KEY',
  MISSING_COMPOSITE_TYPE = 'MISSING_COMPOSITE_TYPE',
  COLUMN_TARGET_COLUMN_MAP_NOT_VALID = 'COLUMN_TARGET_COLUMN_MAP_NOT_VALID',
  COLUMN_NAME_SHOULD_BE_CUSTOM = 'COLUMN_NAME_SHOULD_BE_CUSTOM',
  COLUMN_OBJECT_REFERENCE_INVALID = 'COLUMN_OBJECT_REFERENCE_INVALID',
  COLUMN_NAME_NOT_VALID = 'COLUMN_NAME_NOT_VALID',
  COLUMN_TYPE_NOT_VALID = 'COLUMN_TYPE_NOT_VALID',
  COLUMN_DATA_TYPE_CONFLICT = 'COLUMN_DATA_TYPE_CONFLICT',
  COLUMN_NULLABILITY_CONFLICT = 'COLUMN_NULLABILITY_CONFLICT',
}

export interface WorkspaceHealthTableIssue {
  type:
    | WorkspaceHealthIssueType.MISSING_TABLE
    | WorkspaceHealthIssueType.TABLE_NAME_SHOULD_BE_CUSTOM
    | WorkspaceHealthIssueType.TABLE_TARGET_TABLE_NAME_NOT_VALID
    | WorkspaceHealthIssueType.TABLE_DATA_SOURCE_ID_NOT_VALID
    | WorkspaceHealthIssueType.TABLE_NAME_NOT_VALID;
  objectMetadata: ObjectMetadataEntity;
  message: string;
}

export interface WorkspaceHealthColumnIssue {
  type:
    | WorkspaceHealthIssueType.MISSING_COLUMN
    | WorkspaceHealthIssueType.MISSING_INDEX
    | WorkspaceHealthIssueType.MISSING_FOREIGN_KEY
    | WorkspaceHealthIssueType.MISSING_COMPOSITE_TYPE
    | WorkspaceHealthIssueType.COLUMN_TARGET_COLUMN_MAP_NOT_VALID
    | WorkspaceHealthIssueType.COLUMN_NAME_SHOULD_BE_CUSTOM
    | WorkspaceHealthIssueType.COLUMN_OBJECT_REFERENCE_INVALID
    | WorkspaceHealthIssueType.COLUMN_NAME_NOT_VALID
    | WorkspaceHealthIssueType.COLUMN_TYPE_NOT_VALID
    | WorkspaceHealthIssueType.COLUMN_DATA_TYPE_CONFLICT
    | WorkspaceHealthIssueType.COLUMN_NULLABILITY_CONFLICT;
  fieldMetadata: FieldMetadataEntity;
  columnStructure?: WorkspaceTableStructure;
  message: string;
}

export type WorkspaceHealthIssue =
  | WorkspaceHealthTableIssue
  | WorkspaceHealthColumnIssue;
