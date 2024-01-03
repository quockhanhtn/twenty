import { ObjectMetadataItem } from '@/object-metadata/types/ObjectMetadataItem';
import { useMultiObjectSearchMatchesSearchFilterAndSelectedItemsQuery } from '@/object-record/relation-picker/hooks/useMultiObjectSearchMatchesSearchFilterAndSelectedItemsQuery';
import { useMultiObjectSearchMatchesSearchFilterAndToSelectQuery } from '@/object-record/relation-picker/hooks/useMultiObjectSearchMatchesSearchFilterAndToSelectQuery';
import { ObjectRecord } from '@/object-record/types/ObjectRecord';
import { ObjectRecordIdentifier } from '@/object-record/types/ObjectRecordIdentifier';

export const DEFAULT_SEARCH_REQUEST_LIMIT = 5;

export type ObjectRecordForSelect = {
  objectMetadataItem: ObjectMetadataItem;
  record: ObjectRecord;
  recordIdentifier: ObjectRecordIdentifier;
};

export type SelectedObjectRecordId = {
  objectNameSingular: string;
  id: string;
};

export type MultiObjectSearch = {
  // selectedObjectRecords: ObjectRecordForSelect[];
  filteredSelectedObjectRecords: ObjectRecordForSelect[];
  objectRecordsToSelect: ObjectRecordForSelect[];
  loading: boolean;
};

export const useMultiObjectSearch = ({
  searchFilterValue,
  selectedObjectRecordIds,
  limit,
  excludedObjectRecordIds = [],
}: {
  searchFilterValue: string;
  selectedObjectRecordIds: SelectedObjectRecordId[];
  limit?: number;
  excludedObjectRecordIds?: SelectedObjectRecordId[];
}): MultiObjectSearch => {
  const {
    selectedAndMatchesSearchFilterObjectRecords,
    selectedAndMatchesSearchFilterObjectRecordsLoading,
  } = useMultiObjectSearchMatchesSearchFilterAndSelectedItemsQuery({
    searchFilterValue,
    selectedObjectRecordIds,
    limit,
  });

  const {
    toSelectAndMatchesSearchFilterObjectRecords,
    toSelectAndMatchesSearchFilterObjectRecordsLoading,
  } = useMultiObjectSearchMatchesSearchFilterAndToSelectQuery({
    excludedObjectRecordIds,
    searchFilterValue,
    selectedObjectRecordIds,
    limit,
  });

  return {
    filteredSelectedObjectRecords: selectedAndMatchesSearchFilterObjectRecords,
    objectRecordsToSelect: toSelectAndMatchesSearchFilterObjectRecords,
    loading:
      selectedAndMatchesSearchFilterObjectRecordsLoading ||
      toSelectAndMatchesSearchFilterObjectRecordsLoading,
  };
};
